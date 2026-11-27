// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP VNC/RFAPI YANG-backed CLI
 * Copyright (C) 2026 FRRouting
 */

#include <zebra.h>

#if ENABLE_BGP_VNC

#include "command.h"
#include "northbound_cli.h"
#include "frrstr.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_vnc_nb.h"
#include "bgpd/rfapi/bgp_rfapi_cfg.h"
#include "bgpd/rfapi/rfapi.h"
#include "bgpd/rfapi/rfapi_private.h"

#include "bgpd/bgp_vnc_cli_clippy.c"

void vnc_cli_show_rfp_cfg_cb(struct vty *vty, struct bgp *bgp)
{
	if (bgp && bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT && bgp->rfapi &&
	    bgp->rfapi->rfp_methods.cfg_cb)
		bgp->rfapi->rfp_methods.cfg_cb(vty, bgp->rfapi->rfp);
}

static const struct lyd_node *vnc_cli_candidate_get(struct vty *vty, const char *rel_xpath)
{
	const struct lyd_node *cur;

	if (!vty->candidate_config || !vty->candidate_config->dnode)
		return NULL;
	cur = yang_dnode_get(vty->candidate_config->dnode, VTY_CURR_XPATH);
	if (!cur)
		return NULL;
	if (!rel_xpath)
		return cur;
	return yang_dnode_get(cur, rel_xpath);
}

static int vnc_cli_filter_apply(struct vty *vty, const char *xpath, bool no, const char *name)
{
	if (no) {
		if (name) {
			const struct lyd_node *dnode = vnc_cli_candidate_get(vty, xpath);

			if (!dnode || !strmatch(yang_dnode_get_string(dnode, NULL), name)) {
				vty_out(vty, "%% Filter name \"%s\" does not match\n", name);
				return CMD_WARNING_CONFIG_FAILED;
			}
		}
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	} else {
		nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, name);
	}
	return nb_cli_apply_changes(vty, NULL);
}

/*
 * LIFETIME is any token. A non-numeric word is stored as 0, which is what
 * strtoul() did. Response lifetime is capped at INT32_MAX.
 */
static const char *vnc_cli_lifetime(const char *lifetime, bool infinite, bool cap, char *buf,
				    size_t buflen)
{
	unsigned long val;

	if (infinite)
		return "infinite";
	val = strtoul(lifetime, NULL, 10);
	if (cap && val > INT32_MAX)
		val = INT32_MAX;
	snprintfrr(buf, buflen, "%lu", val);
	return buf;
}


/*
 * ===================================================================
 * VNC (Virtual Network Control / RFAPI) CLI Commands
 * ===================================================================
 */

/* --- VNC defaults node entry/exit --- */

DEFPY_YANG_NOSH(vnc_defaults_cli,
	vnc_defaults_cli_cmd,
	"vnc defaults",
	"VNC/RFAPI configuration\n"
	"Configure default NVE group settings\n")
{
	char xpath_abs[XPATH_MAXLEN + 256];
	int ret;

	nb_cli_enqueue_change(vty, "./frr-bgp-vnc:vnc/defaults", NB_OP_CREATE, NULL);
	ret = nb_cli_apply_changes_clear_pending(vty, NULL);
	if (ret != CMD_SUCCESS)
		return ret;

	snprintfrr(xpath_abs, sizeof(xpath_abs), "%s/frr-bgp-vnc:vnc/defaults", VTY_CURR_XPATH);
	VTY_PUSH_XPATH(BGP_VNC_DEFAULTS_NODE, xpath_abs);
	return CMD_SUCCESS;
}

DEFPY_YANG_NOSH(exit_vnc_cli,
	exit_vnc_cli_cmd,
	"exit-vnc",
	"Exit VNC configuration mode\n")
{
	if (vty->node == BGP_VNC_DEFAULTS_NODE || vty->node == BGP_VNC_NVE_GROUP_NODE ||
	    vty->node == BGP_VNC_L2_GROUP_NODE) {
		vty->node = BGP_NODE;
		if (vty->xpath_index > 0)
			vty->xpath_index--;
	}
	return CMD_SUCCESS;
}

/* --- VNC defaults: rd --- */

DEFPY_YANG(vnc_defaults_rd_cli,
	vnc_defaults_rd_cli_cmd,
	"rd WORD$rd_str",
	"Specify default route distinguisher\n"
	"Route distinguisher (ASN:NN or IP:NN or auto:vn:NN)\n")
{
	nb_cli_enqueue_change(vty, "./rd", NB_OP_MODIFY, rd_str);
	return nb_cli_apply_changes(vty, NULL);
}

/* --- VNC defaults: response-lifetime --- */

DEFPY_YANG(vnc_defaults_response_lifetime_cli,
	vnc_defaults_response_lifetime_cli_cmd,
	"response-lifetime <LIFETIME$lifetime|infinite$infinite>",
	"Specify default response lifetime\n"
	"Response lifetime in seconds\n"
	"Infinite response lifetime\n")
{
	char buf[32];

	nb_cli_enqueue_change(vty, "./response-lifetime", NB_OP_MODIFY,
			      vnc_cli_lifetime(lifetime, infinite, true, buf, sizeof(buf)));
	return nb_cli_apply_changes(vty, NULL);
}

/* --- VNC defaults/nve-group/vrf-policy: rt --- */

DEFPY_YANG(vnc_rt_cli,
	vnc_rt_cli_cmd,
	"rt <import|export|both>$direction RTLIST...",
	"Specify route targets\n"
	"Import filter\n"
	"Export filter\n"
	"Import and export\n"
	"Space separated route target list (A.B.C.D:MN|EF:OPQR|GHJK:MN)\n")
{
	char rt_str[512] = {};
	int i;

	/* Concatenate all RT values into a single space-separated string */
	for (i = 2; i < argc; i++) {
		if (i > 2)
			strlcat(rt_str, " ", sizeof(rt_str));
		strlcat(rt_str, argv[i]->arg, sizeof(rt_str));
	}

	if (!strcmp(direction, "import") || !strcmp(direction, "both"))
		nb_cli_enqueue_change(vty, "./rt-import", NB_OP_MODIFY, rt_str);
	if (!strcmp(direction, "export") || !strcmp(direction, "both"))
		nb_cli_enqueue_change(vty, "./rt-export", NB_OP_MODIFY, rt_str);

	return nb_cli_apply_changes(vty, NULL);
}

/* --- VNC nve-group node entry/exit --- */

DEFPY_YANG_NOSH(vnc_nve_group_cli,
	vnc_nve_group_cli_cmd,
	"vnc nve-group WORD$name",
	"VNC/RFAPI configuration\n"
	"Configure a NVE group\n"
	"NVE group name\n")
{
	char xpath[XPATH_MAXLEN];
	char xpath_abs[XPATH_MAXLEN + 256];
	int ret;

	snprintfrr(xpath, sizeof(xpath), "./frr-bgp-vnc:vnc/nve-group[name='%s']", name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	ret = nb_cli_apply_changes_clear_pending(vty, NULL);
	if (ret != CMD_SUCCESS)
		return ret;

	snprintfrr(xpath_abs, sizeof(xpath_abs), "%s/frr-bgp-vnc:vnc/nve-group[name='%s']",
		   VTY_CURR_XPATH, name);
	VTY_PUSH_XPATH(BGP_VNC_NVE_GROUP_NODE, xpath_abs);
	return CMD_SUCCESS;
}

DEFPY_YANG(no_vnc_nve_group_cli,
	no_vnc_nve_group_cli_cmd,
	"no vnc nve-group WORD$name",
	NO_STR
	"VNC/RFAPI configuration\n"
	"Delete a NVE group\n"
	"NVE group name\n")
{
	char xpath[XPATH_MAXLEN];

	snprintfrr(xpath, sizeof(xpath), "./frr-bgp-vnc:vnc/nve-group[name='%s']", name);
	if (!vnc_cli_candidate_get(vty, xpath)) {
		vty_out(vty, "No NVE group named \"%s\"\n", name);
		return CMD_WARNING_CONFIG_FAILED;
	}
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

/* --- NVE group: prefix vn/un --- */

DEFPY_YANG(vnc_nve_group_prefix_cli,
	vnc_nve_group_prefix_cli_cmd,
	"prefix <vn|un>$which <A.B.C.D/M|X:X::X:X/M>$prefix",
	"Specify matching NVE virtual/underlay address\n"
	"Virtual network address\n"
	"Underlay network address\n"
	"IPv4 prefix\n"
	"IPv6 prefix\n")
{
	if (!strcmp(which, "vn"))
		nb_cli_enqueue_change(vty, "./prefix-vn", NB_OP_MODIFY, prefix_str);
	else
		nb_cli_enqueue_change(vty, "./prefix-un", NB_OP_MODIFY, prefix_str);
	return nb_cli_apply_changes(vty, NULL);
}

/* --- NVE group: rd --- */

DEFPY_YANG(vnc_nve_group_rd_cli,
	vnc_nve_group_rd_cli_cmd,
	"rd WORD$rd_str",
	"Specify route distinguisher\n"
	"Route distinguisher (ASN:NN or IP:NN or auto:vn:NN)\n")
{
	nb_cli_enqueue_change(vty, "./rd", NB_OP_MODIFY, rd_str);
	return nb_cli_apply_changes(vty, NULL);
}

/* --- NVE group: response-lifetime --- */

DEFPY_YANG(vnc_nve_group_response_lifetime_cli,
	vnc_nve_group_response_lifetime_cli_cmd,
	"response-lifetime <LIFETIME$lifetime|infinite$infinite>",
	"Specify response lifetime\n"
	"Response lifetime in seconds\n"
	"Infinite response lifetime\n")
{
	char buf[32];

	nb_cli_enqueue_change(vty, "./response-lifetime", NB_OP_MODIFY,
			      vnc_cli_lifetime(lifetime, infinite, true, buf, sizeof(buf)));
	return nb_cli_apply_changes(vty, NULL);
}

/* --- VRF policy node entry/exit --- */

DEFPY_YANG_NOSH(vrf_policy_cli,
	vrf_policy_cli_cmd,
	"vrf-policy WORD$name",
	"Configure a VRF policy group\n"
	"VRF policy name\n")
{
	char xpath[XPATH_MAXLEN];
	char xpath_abs[XPATH_MAXLEN + 256];
	int ret;

	snprintfrr(xpath, sizeof(xpath), "./frr-bgp-vnc:vnc/vrf-policy[name='%s']", name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	ret = nb_cli_apply_changes_clear_pending(vty, NULL);
	if (ret != CMD_SUCCESS)
		return ret;

	snprintfrr(xpath_abs, sizeof(xpath_abs), "%s/frr-bgp-vnc:vnc/vrf-policy[name='%s']",
		   VTY_CURR_XPATH, name);
	VTY_PUSH_XPATH(BGP_VRF_POLICY_NODE, xpath_abs);
	return CMD_SUCCESS;
}

DEFPY_YANG(no_vrf_policy_cli,
	no_vrf_policy_cli_cmd,
	"no vrf-policy WORD$name",
	NO_STR
	"Delete a VRF policy group\n"
	"VRF policy name\n")
{
	char xpath[XPATH_MAXLEN];

	snprintfrr(xpath, sizeof(xpath), "./frr-bgp-vnc:vnc/vrf-policy[name='%s']", name);
	if (!vnc_cli_candidate_get(vty, xpath)) {
		vty_out(vty, "No NVE group named \"%s\"\n", name);
		return CMD_WARNING_CONFIG_FAILED;
	}
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG_NOSH(exit_vrf_policy_cli,
	exit_vrf_policy_cli_cmd,
	"exit-vrf-policy",
	"Exit VRF policy configuration mode\n")
{
	if (vty->node == BGP_VRF_POLICY_NODE) {
		vty->node = BGP_NODE;
		if (vty->xpath_index > 0)
			vty->xpath_index--;
	}
	return CMD_SUCCESS;
}

/* --- VRF policy: label --- */

DEFPY_YANG(vrf_policy_label_cli,
	vrf_policy_label_cli_cmd,
	"[no] label [(0-1048575)$label]",
	NO_STR
	"Specify label for this VRF policy\n"
	"MPLS label value\n")
{
	if (no)
		nb_cli_enqueue_change(vty, "./label", NB_OP_DESTROY, NULL);
	else if (!label_str) {
		vty_out(vty, "%% Missing label value\n");
		return CMD_WARNING_CONFIG_FAILED;
	} else
		nb_cli_enqueue_change(vty, "./label", NB_OP_MODIFY, label_str);
	return nb_cli_apply_changes(vty, NULL);
}

/* --- VRF policy: rd --- */

DEFPY_YANG(vrf_policy_rd_cli,
	vrf_policy_rd_cli_cmd,
	"rd WORD$rd_str",
	"Specify route distinguisher\n"
	"Route distinguisher (ASN:NN or IP:NN or auto:nh:NN)\n")
{
	nb_cli_enqueue_change(vty, "./rd", NB_OP_MODIFY, rd_str);
	return nb_cli_apply_changes(vty, NULL);
}

/* --- VRF policy: nexthop --- */

DEFPY_YANG(vrf_policy_nexthop_cli,
	vrf_policy_nexthop_cli_cmd,
	"nexthop <A.B.C.D|X:X::X:X|self>$nh",
	"Specify next-hop address\n"
	"IPv4 address\n"
	"IPv6 address\n"
	"Use own address\n")
{
	nb_cli_enqueue_change(vty, "./nexthop", NB_OP_MODIFY, nh);
	return nb_cli_apply_changes(vty, NULL);
}

/* --- VNC export bgp mode --- */

DEFPY_YANG(vnc_export_bgp_mode_cli,
	vnc_export_bgp_mode_cli_cmd,
	"vnc export bgp mode <group-nve|ce|none|registering-nve>$mode",
	"VNC/RFAPI configuration\n"
	"Export to other protocols\n"
	"Export to BGP\n"
	"Set export mode\n"
	"Export using NVE group configuration\n"
	"Export based on CE\n"
	"Disable export\n"
	"Export based on registering NVE\n")
{
	nb_cli_enqueue_change(vty, "./frr-bgp-vnc:vnc/export/bgp/mode", NB_OP_MODIFY, mode);
	return nb_cli_apply_changes(vty, NULL);
}

/* --- VNC export bgp group-nve group --- */

DEFPY_YANG(vnc_export_bgp_group_nve_cli,
	vnc_export_bgp_group_nve_cli_cmd,
	"vnc export bgp group-nve group WORD$name",
	"VNC/RFAPI configuration\n"
	"Export to other protocols\n"
	"Export to BGP\n"
	"NVE group mode\n"
	"Specify NVE group\n"
	"NVE group name\n")
{
	char xpath[XPATH_MAXLEN];

	snprintfrr(xpath, sizeof(xpath), "./frr-bgp-vnc:vnc/export/bgp/group-nve-group[.='%s']",
		   name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

static int vnc_cli_no_export_group_nve(struct vty *vty, const char *proto, const char *name)
{
	char xpath[XPATH_MAXLEN];

	if (name) {
		snprintfrr(xpath, sizeof(xpath),
			   "./frr-bgp-vnc:vnc/export/%s/group-nve-group[.='%s']", proto, name);
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
		return nb_cli_apply_changes(vty, NULL);
	}

	snprintfrr(xpath, sizeof(xpath), "./frr-bgp-vnc:vnc/export/%s", proto);
	const struct lyd_node *exp = vnc_cli_candidate_get(vty, xpath);

	if (exp) {
		const struct lyd_node *child;

		LY_LIST_FOR (lyd_child(exp), child) {
			if (strcmp(child->schema->name, "group-nve-group"))
				continue;
			snprintfrr(xpath, sizeof(xpath),
				   "./frr-bgp-vnc:vnc/export/%s/group-nve-group[.='%s']", proto,
				   lyd_get_value(child));
			nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
		}
	}
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_vnc_export_bgp_group_nve_cli,
	no_vnc_export_bgp_group_nve_cli_cmd,
	"no vnc export bgp group-nve group [WORD$name]",
	NO_STR
	"VNC/RFAPI configuration\n"
	"Export to other protocols\n"
	"Export to BGP\n"
	"NVE group mode\n"
	"Specify NVE group\n"
	"NVE group name\n")
{
	return vnc_cli_no_export_group_nve(vty, "bgp", name);
}

ALIAS_ATTR(no_vnc_export_bgp_group_nve_cli, vnc_export_bgp_group_nve_no_group_cmd,
	   "vnc export bgp group-nve no group [WORD$name]",
	   "VNC/RFAPI configuration\n"
	   "Export to other protocols\n"
	   "Export to BGP\n"
	   "NVE group mode\n"
	   NO_STR
	   "Specify NVE group\n"
	   "NVE group name\n",
	   CMD_ATTR_YANG);

/* --- VNC export zebra mode / group-nve --- */

DEFPY_YANG(vnc_export_zebra_mode_cli,
	   vnc_export_zebra_mode_cli_cmd,
	   "vnc export zebra mode <group-nve|ce|none|registering-nve>$mode",
	   "VNC/RFAPI configuration\n"
	   "Export to other protocols\n"
	   "Export to Zebra (experimental)\n"
	   "Set export mode\n"
	   "Export using NVE group configuration\n"
	   "Export routes with NVE connected router next-hops\n"
	   "Disable export\n"
	   "Export based on registering NVE\n")
{
	if (strmatch(mode, "ce")) {
		vty_out(vty, "Changing modes for zebra export not implemented yet\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	nb_cli_enqueue_change(vty, "./frr-bgp-vnc:vnc/export/zebra/mode", NB_OP_MODIFY, mode);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(vnc_export_zebra_group_nve_cli,
	   vnc_export_zebra_group_nve_cli_cmd,
	   "vnc export zebra group-nve group WORD$name",
	   "VNC/RFAPI configuration\n"
	   "Export to other protocols\n"
	   "Export to Zebra (experimental)\n"
	   "NVE group mode\n"
	   "Specify NVE group\n"
	   "NVE group name\n")
{
	char xpath[XPATH_MAXLEN];

	snprintfrr(xpath, sizeof(xpath), "./frr-bgp-vnc:vnc/export/zebra/group-nve-group[.='%s']",
		   name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_vnc_export_zebra_group_nve_cli,
	   no_vnc_export_zebra_group_nve_cli_cmd,
	   "no vnc export zebra group-nve group [WORD$name]",
	   NO_STR
	   "VNC/RFAPI configuration\n"
	   "Export to other protocols\n"
	   "Export to Zebra (experimental)\n"
	   "NVE group mode\n"
	   "Specify NVE group\n"
	   "NVE group name\n")
{
	return vnc_cli_no_export_group_nve(vty, "zebra", name);
}

ALIAS_ATTR(no_vnc_export_zebra_group_nve_cli, vnc_export_zebra_group_nve_no_group_cmd,
	   "vnc export zebra group-nve no group [WORD$name]",
	   "VNC/RFAPI configuration\n"
	   "Export to other protocols\n"
	   "Export to Zebra (experimental)\n"
	   "NVE group mode\n"
	   NO_STR
	   "Specify NVE group\n"
	   "NVE group name\n",
	   CMD_ATTR_YANG);

/* --- VNC redistribute mode --- */

DEFPY_YANG(vnc_redistribute_mode_cli,
	vnc_redistribute_mode_cli_cmd,
	"vnc redistribute mode <plain|nve-group|resolve-nve>$mode",
	"VNC/RFAPI configuration\n"
	"Redistribute configuration\n"
	"Set redistribute mode\n"
	"Plain redistribution\n"
	"Use NVE group\n"
	"Resolve NVE\n")
{
	nb_cli_enqueue_change(vty, "./frr-bgp-vnc:vnc/redistribute/mode", NB_OP_MODIFY, mode);
	return nb_cli_apply_changes(vty, NULL);
}

/* --- VNC redistribute ipv4/ipv6 source --- */

DEFPY_YANG(vnc_redistribute_source_cli,
	vnc_redistribute_source_cli_cmd,
	"vnc redistribute <ipv4|ipv6>$afi <bgp|bgp-direct|bgp-direct-to-nve-groups|connected|kernel|ospf|rip|static>$source",
	"VNC/RFAPI configuration\n"
	"Redistribute from other protocols\n"
	"IPv4 redistribution\n"
	"IPv6 redistribution\n"
	"From BGP\n"
	"From BGP directly\n"
	"From BGP direct to NVE groups\n"
	"Connected routes\n"
	"Kernel routes\n"
	"OSPF routes\n"
	"RIP routes\n"
	"Static routes\n")
{
	char xpath[XPATH_MAXLEN];

	if (!strcmp(afi, "ipv4"))
		snprintfrr(xpath, sizeof(xpath),
			   "./frr-bgp-vnc:vnc/redistribute/ipv4-source[.='%s']", source);
	else
		snprintfrr(xpath, sizeof(xpath),
			   "./frr-bgp-vnc:vnc/redistribute/ipv6-source[.='%s']", source);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	if (!strcmp(source, "bgp-direct-to-nve-groups") &&
	    vnc_cli_candidate_get(vty,
				  "./frr-bgp-vnc:vnc/redistribute/bgp-direct-to-nve-groups-view"))
		nb_cli_enqueue_change(vty,
				      "./frr-bgp-vnc:vnc/redistribute/bgp-direct-to-nve-groups-view",
				      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_vnc_redistribute_source_cli,
	no_vnc_redistribute_source_cli_cmd,
	"no vnc redistribute <ipv4|ipv6>$afi <bgp|bgp-direct|bgp-direct-to-nve-groups|connected|kernel|ospf|rip|static>$source",
	NO_STR
	"VNC/RFAPI configuration\n"
	"Redistribute from other protocols\n"
	"IPv4 redistribution\n"
	"IPv6 redistribution\n"
	"From BGP\n"
	"From BGP directly\n"
	"From BGP direct to NVE groups\n"
	"Connected routes\n"
	"Kernel routes\n"
	"OSPF routes\n"
	"RIP routes\n"
	"Static routes\n")
{
	char xpath[XPATH_MAXLEN];
	const char *other_xpath;

	if (!strcmp(afi, "ipv4")) {
		snprintfrr(xpath, sizeof(xpath),
			   "./frr-bgp-vnc:vnc/redistribute/ipv4-source[.='%s']", source);
		other_xpath =
			"./frr-bgp-vnc:vnc/redistribute/ipv6-source[.='bgp-direct-to-nve-groups']";
	} else {
		snprintfrr(xpath, sizeof(xpath),
			   "./frr-bgp-vnc:vnc/redistribute/ipv6-source[.='%s']", source);
		other_xpath =
			"./frr-bgp-vnc:vnc/redistribute/ipv4-source[.='bgp-direct-to-nve-groups']";
	}
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	if (!strcmp(source, "bgp-direct-to-nve-groups") &&
	    !vnc_cli_candidate_get(vty, other_xpath))
		nb_cli_enqueue_change(vty,
				      "./frr-bgp-vnc:vnc/redistribute/bgp-direct-to-nve-groups-view",
				      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

/* --- VNC redistribute nve-group / lifetime / roo / exterior view --- */

DEFPY_YANG(vnc_redistribute_nvegroup_cli,
	   vnc_redistribute_nvegroup_cli_cmd,
	   "[no] vnc redistribute nve-group [NAME$name]",
	   NO_STR
	   "VNC/RFAPI configuration\n"
	   "Redistribute from other protocol\n"
	   "Assign an NVE group to redistributed routes\n"
	   "Group name\n")
{
	if (no) {
		nb_cli_enqueue_change(vty, "./frr-bgp-vnc:vnc/redistribute/nve-group",
				      NB_OP_DESTROY, NULL);
	} else if (!name) {
		vty_out(vty, "%% Missing NVE group name\n");
		return CMD_WARNING_CONFIG_FAILED;
	} else {
		nb_cli_enqueue_change(vty, "./frr-bgp-vnc:vnc/redistribute/nve-group",
				      NB_OP_MODIFY, name);
	}
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(vnc_redistribute_lifetime_cli,
	   vnc_redistribute_lifetime_cli_cmd,
	   "vnc redistribute lifetime <LIFETIME$lifetime|infinite$infinite>",
	   "VNC/RFAPI configuration\n"
	   "Redistribute\n"
	   "Assign a lifetime to redistributed routes\n"
	   "Lifetime value (32 bit)\n"
	   "Allow lifetime to never expire\n")
{
	char buf[32];

	nb_cli_enqueue_change(vty, "./frr-bgp-vnc:vnc/redistribute/lifetime", NB_OP_MODIFY,
			      vnc_cli_lifetime(lifetime, infinite, false, buf, sizeof(buf)));
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(vnc_redistribute_rh_roo_localadmin_cli,
	   vnc_redistribute_rh_roo_localadmin_cli_cmd,
	   "vnc redistribute resolve-nve roo-ec-local-admin (0-65535)$localadmin",
	   "VNC/RFAPI configuration\n"
	   "Redistribute routes into VNC\n"
	   "Resolve-NVE mode\n"
	   "Route Origin Extended Community Local Admin Field\n"
	   "Field value\n")
{
	nb_cli_enqueue_change(vty, "./frr-bgp-vnc:vnc/redistribute/resolve-nve-roo-ec-local-admin",
			      NB_OP_MODIFY, localadmin_str);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(vnc_redistribute_bgp_exterior_cli,
	   vnc_redistribute_bgp_exterior_cli_cmd,
	   "vnc redistribute <ipv4|ipv6>$afi bgp-direct-to-nve-groups view NAME$view",
	   "VNC/RFAPI configuration\n"
	   "Redistribute routes into VNC\n"
	   "IPv4 routes\n"
	   "IPv6 routes\n"
	   "From BGP without Zebra, only to configured NVE groups\n"
	   "From BGP view\n"
	   "BGP view name\n")
{
	char xpath[XPATH_MAXLEN];

	if (!strcmp(afi, "ipv4"))
		snprintfrr(xpath, sizeof(xpath),
			   "./frr-bgp-vnc:vnc/redistribute/ipv4-source[.='bgp-direct-to-nve-groups']");
	else
		snprintfrr(xpath, sizeof(xpath),
			   "./frr-bgp-vnc:vnc/redistribute/ipv6-source[.='bgp-direct-to-nve-groups']");
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	nb_cli_enqueue_change(vty, "./frr-bgp-vnc:vnc/redistribute/bgp-direct-to-nve-groups-view",
			      NB_OP_MODIFY, view);
	return nb_cli_apply_changes(vty, NULL);
}

/* --- RFP holddown-factor and full-table-download --- */

DEFPY_YANG(rfp_holddown_factor_cli,
	   rfp_holddown_factor_cli_cmd,
	   "rfp holddown-factor (0-4294967295)$factor",
	   "RFP configuration\n"
	   "Set holddown factor as percentage of registration lifetime\n"
	   "Percentage of registration lifetime\n")
{
	nb_cli_enqueue_change(vty, "./frr-bgp-vnc:vnc/rfp/holddown-factor", NB_OP_MODIFY,
			      factor_str);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(rfp_full_table_download_cli,
	   rfp_full_table_download_cli_cmd,
	   "rfp full-table-download <on|off>$mode",
	   "RFP configuration\n"
	   "Enable/disable full table download\n"
	   "Enable full table download\n"
	   "Disable full table download\n")
{
	nb_cli_enqueue_change(vty, "./frr-bgp-vnc:vnc/rfp/full-table-download", NB_OP_MODIFY, mode);
	return nb_cli_apply_changes(vty, NULL);
}

static void vnc_rd_cli_show_helper(struct vty *vty, const char *rd_str, bool is_vrf_policy,
				   const char *indent)
{
	struct prefix_rd prd;

	if (!vnc_nb_parse_rd(rd_str, &prd, is_vrf_policy)) {
		if (prd.family == AF_UNIX) {
			uint16_t nn = ((prd.val[6] << 8) & 0xff00) | (prd.val[7] & 0x00ff);

			vty_out(vty, "%srd auto:%s:%u\n", indent, is_vrf_policy ? "nh" : "vn", nn);
		} else {
			vty_out(vty, "%srd %pRDP\n", indent, &prd);
		}
	} else {
		vty_out(vty, "%srd %s\n", indent, rd_str);
	}
}

static void vnc_prefix_cli_show_helper(struct vty *vty, const char *which, const char *pfx_str,
				       const char *indent)
{
	struct prefix p;

	if (str2prefix(pfx_str, &p)) {
		apply_mask(&p);
		vty_out(vty, "%sprefix %s %pFX\n", indent, which, &p);
	} else {
		vty_out(vty, "%sprefix %s %s\n", indent, which, pfx_str);
	}
}

/* Helper to emit RT lines: compares canonical ecommunities and emits "rt both" if equal */
static void vnc_rt_cli_show_helper(struct vty *vty, const struct lyd_node *dnode,
				   const char *indent)
{
	const char *rt_import = NULL;
	const char *rt_export = NULL;
	struct ecommunity *ec_imp = NULL;
	struct ecommunity *ec_exp = NULL;

	if (yang_dnode_exists(dnode, "rt-import")) {
		rt_import = yang_dnode_get_string(dnode, "rt-import");
		ec_imp = ecommunity_str2com(rt_import, ECOMMUNITY_ROUTE_TARGET, 0);
	}
	if (yang_dnode_exists(dnode, "rt-export")) {
		rt_export = yang_dnode_get_string(dnode, "rt-export");
		ec_exp = ecommunity_str2com(rt_export, ECOMMUNITY_ROUTE_TARGET, 0);
	}

	if (ec_imp && ec_exp && ecommunity_cmp(ec_imp, ec_exp)) {
		char *b = ecommunity_ecom2str(ec_imp, ECOMMUNITY_FORMAT_ROUTE_MAP,
					      ECOMMUNITY_ROUTE_TARGET);
		vty_out(vty, "%srt both %s\n", indent, b);
		XFREE(MTYPE_ECOMMUNITY_STR, b);
	} else if (ec_imp || ec_exp) {
		if (ec_imp) {
			char *b = ecommunity_ecom2str(ec_imp, ECOMMUNITY_FORMAT_ROUTE_MAP,
						      ECOMMUNITY_ROUTE_TARGET);
			vty_out(vty, "%srt import %s\n", indent, b);
			XFREE(MTYPE_ECOMMUNITY_STR, b);
		}
		if (ec_exp) {
			char *b = ecommunity_ecom2str(ec_exp, ECOMMUNITY_FORMAT_ROUTE_MAP,
						      ECOMMUNITY_ROUTE_TARGET);
			vty_out(vty, "%srt export %s\n", indent, b);
			XFREE(MTYPE_ECOMMUNITY_STR, b);
		}
	} else if (rt_import && rt_export && !strcmp(rt_import, rt_export)) {
		vty_out(vty, "%srt both %s\n", indent, rt_import);
	} else {
		if (rt_import)
			vty_out(vty, "%srt import %s\n", indent, rt_import);
		if (rt_export)
			vty_out(vty, "%srt export %s\n", indent, rt_export);
	}

	if (ec_imp)
		ecommunity_free(&ec_imp);
	if (ec_exp)
		ecommunity_free(&ec_exp);
}

static bool vnc_defaults_has_nondefault(const struct lyd_node *dnode, bool show_defaults)
{
	if (yang_dnode_exists(dnode, "rd") || yang_dnode_exists(dnode, "l2rd") ||
	    yang_dnode_exists(dnode, "rt-import") || yang_dnode_exists(dnode, "rt-export"))
		return true;
	if (yang_dnode_exists(dnode, "response-lifetime")) {
		const char *val = yang_dnode_get_string(dnode, "response-lifetime");

		if (show_defaults || strcmp(val, "3600") != 0)
			return true;
	}
	return false;
}

static bool vnc_defaults_should_show(const struct lyd_node *dnode, bool show_defaults)
{
	const struct lyd_node *vnc = lyd_parent(dnode);

	if (vnc_defaults_has_nondefault(dnode, show_defaults))
		return true;
	if (vnc && yang_dnode_exists(vnc, "./nve-group"))
		return true;
	return false;
}

void vnc_cli_show(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/*
	 * Classic bgp_rfapi_cfg_write() always emits "vnc defaults" when any
	 * NVE group exists, even if no explicit default leaves were set.
	 */
	if (!yang_dnode_exists(dnode, "./defaults") && yang_dnode_exists(dnode, "./nve-group")) {
		struct bgp *bgp = bgp_nb_vnc_get_bgp(dnode);

		vty_out(vty, " vnc defaults\n");
		if (bgp && bgp->rfapi && bgp->rfapi_cfg && bgp->rfapi->rfp_methods.cfg_group_cb)
			bgp->rfapi->rfp_methods.cfg_group_cb(vty, bgp->rfapi->rfp,
							     RFAPI_RFP_CFG_GROUP_DEFAULT, NULL,
							     bgp->rfapi_cfg->default_rfp_cfg);
		vty_out(vty, "  exit-vnc\n");
	}
}

void vnc_rfp_cli_show(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	if (yang_dnode_exists(dnode, "holddown-factor")) {
		uint32_t val = yang_dnode_get_uint32(dnode, "holddown-factor");

		if (val != 0 || show_defaults)
			vty_out(vty, " rfp holddown-factor %u\n", val);
	}
	if (yang_dnode_exists(dnode, "full-table-download")) {
		const char *mode = yang_dnode_get_string(dnode, "full-table-download");

		if (!strcmp(mode, "on") || show_defaults)
			vty_out(vty, " rfp full-table-download %s\n", mode);
	}
}

void vnc_defaults_cli_show(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	struct bgp *bgp;

	if (!vnc_defaults_should_show(dnode, show_defaults))
		return;

	vty_out(vty, " vnc defaults\n");

	if (yang_dnode_exists(dnode, "rd"))
		vnc_rd_cli_show_helper(vty, yang_dnode_get_string(dnode, "rd"), false, "  ");
	if (yang_dnode_exists(dnode, "response-lifetime")) {
		const char *val = yang_dnode_get_string(dnode, "response-lifetime");

		if (show_defaults || strcmp(val, "3600") != 0)
			vty_out(vty, "  response-lifetime %s\n", val);
	}
	if (yang_dnode_exists(dnode, "l2rd"))
		vty_out(vty, "  l2rd %s\n", yang_dnode_get_string(dnode, "l2rd"));
	vnc_rt_cli_show_helper(vty, dnode, "  ");

	bgp = bgp_nb_vnc_get_bgp(dnode);
	if (bgp && bgp->rfapi && bgp->rfapi_cfg && bgp->rfapi->rfp_methods.cfg_group_cb)
		bgp->rfapi->rfp_methods.cfg_group_cb(vty, bgp->rfapi->rfp,
						     RFAPI_RFP_CFG_GROUP_DEFAULT, NULL,
						     bgp->rfapi_cfg->default_rfp_cfg);
}

void vnc_defaults_cli_show_end(struct vty *vty, const struct lyd_node *dnode)
{
	if (!vnc_defaults_should_show(dnode, false))
		return;
	vty_out(vty, "  exit-vnc\n");
}

void vnc_nve_group_cli_show(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const char *name = yang_dnode_get_string(dnode, "name");
	struct bgp *bgp = bgp_nb_vnc_get_bgp(dnode);
	struct rfapi_nve_group_cfg *rfg = nb_running_get_entry_non_rec(dnode, NULL, false);

	vty_out(vty, " vnc nve-group %s\n", name);

	if (yang_dnode_exists(dnode, "prefix-vn"))
		vnc_prefix_cli_show_helper(vty, "vn", yang_dnode_get_string(dnode, "prefix-vn"),
					   "  ");
	if (yang_dnode_exists(dnode, "prefix-un"))
		vnc_prefix_cli_show_helper(vty, "un", yang_dnode_get_string(dnode, "prefix-un"),
					   "  ");
	if (yang_dnode_exists(dnode, "rd"))
		vnc_rd_cli_show_helper(vty, yang_dnode_get_string(dnode, "rd"), false, "  ");
	if (yang_dnode_exists(dnode, "response-lifetime"))
		vty_out(vty, "  response-lifetime %s\n",
			yang_dnode_get_string(dnode, "response-lifetime"));
	if (yang_dnode_exists(dnode, "l2rd"))
		vty_out(vty, "  l2rd %s\n", yang_dnode_get_string(dnode, "l2rd"));
	vnc_rt_cli_show_helper(vty, dnode, "  ");
	if (yang_dnode_exists(dnode, "bgp-export-ipv4-prefix-list"))
		vty_out(vty, "  export bgp ipv4 prefix-list %s\n",
			yang_dnode_get_string(dnode, "bgp-export-ipv4-prefix-list"));
	if (yang_dnode_exists(dnode, "bgp-export-ipv6-prefix-list"))
		vty_out(vty, "  export bgp ipv6 prefix-list %s\n",
			yang_dnode_get_string(dnode, "bgp-export-ipv6-prefix-list"));
	if (yang_dnode_exists(dnode, "zebra-export-ipv4-prefix-list"))
		vty_out(vty, "  export zebra ipv4 prefix-list %s\n",
			yang_dnode_get_string(dnode, "zebra-export-ipv4-prefix-list"));
	if (yang_dnode_exists(dnode, "zebra-export-ipv6-prefix-list"))
		vty_out(vty, "  export zebra ipv6 prefix-list %s\n",
			yang_dnode_get_string(dnode, "zebra-export-ipv6-prefix-list"));
	if (yang_dnode_exists(dnode, "bgp-export-route-map"))
		vty_out(vty, "  export bgp route-map %s\n",
			yang_dnode_get_string(dnode, "bgp-export-route-map"));
	if (yang_dnode_exists(dnode, "zebra-export-route-map"))
		vty_out(vty, "  export zebra route-map %s\n",
			yang_dnode_get_string(dnode, "zebra-export-route-map"));
	if (yang_dnode_exists(dnode, "bgp-direct-ipv4-prefix-list"))
		vty_out(vty, "  redistribute bgp-direct ipv4 prefix-list %s\n",
			yang_dnode_get_string(dnode, "bgp-direct-ipv4-prefix-list"));
	if (yang_dnode_exists(dnode, "bgp-direct-ipv6-prefix-list"))
		vty_out(vty, "  redistribute bgp-direct ipv6 prefix-list %s\n",
			yang_dnode_get_string(dnode, "bgp-direct-ipv6-prefix-list"));
	if (yang_dnode_exists(dnode, "bgp-direct-route-map"))
		vty_out(vty, "  redistribute bgp-direct route-map %s\n",
			yang_dnode_get_string(dnode, "bgp-direct-route-map"));

	if (bgp && bgp->rfapi && bgp->rfapi->rfp_methods.cfg_group_cb)
		bgp->rfapi->rfp_methods.cfg_group_cb(vty, bgp->rfapi->rfp,
						     RFAPI_RFP_CFG_GROUP_NVE, name,
						     rfg ? rfg->rfp_cfg : NULL);
}

void vnc_nve_group_cli_show_end(struct vty *vty, const struct lyd_node *dnode)
{
	vty_out(vty, "  exit-vnc\n");
}

void vnc_vrf_policy_cli_show(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, " vrf-policy %s\n", yang_dnode_get_string(dnode, "name"));

	if (yang_dnode_exists(dnode, "label"))
		vty_out(vty, "  label %s\n", yang_dnode_get_string(dnode, "label"));
	if (yang_dnode_exists(dnode, "rd"))
		vnc_rd_cli_show_helper(vty, yang_dnode_get_string(dnode, "rd"), true, "  ");
	vnc_rt_cli_show_helper(vty, dnode, "  ");
	if (yang_dnode_exists(dnode, "nexthop"))
		vty_out(vty, "  nexthop %s\n", yang_dnode_get_string(dnode, "nexthop"));
	if (yang_dnode_exists(dnode, "ipv4-export-prefix-list"))
		vty_out(vty, "  export ipv4 prefix-list %s\n",
			yang_dnode_get_string(dnode, "ipv4-export-prefix-list"));
	if (yang_dnode_exists(dnode, "ipv6-export-prefix-list"))
		vty_out(vty, "  export ipv6 prefix-list %s\n",
			yang_dnode_get_string(dnode, "ipv6-export-prefix-list"));
	if (yang_dnode_exists(dnode, "export-route-map"))
		vty_out(vty, "  export route-map %s\n",
			yang_dnode_get_string(dnode, "export-route-map"));
}

void vnc_vrf_policy_cli_show_end(struct vty *vty, const struct lyd_node *dnode)
{
	vty_out(vty, "  exit-vrf-policy\n");
}

void vnc_export_bgp_cli_show(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const struct lyd_node *child;
	const char *mode;

	if (yang_dnode_exists(dnode, "mode")) {
		mode = yang_dnode_get_string(dnode, "mode");
		if (strcmp(mode, "none"))
			vty_out(vty, " vnc export bgp mode %s\n", mode);
	}

	/* Emit group-nve-group entries */
	LY_LIST_FOR (lyd_child(dnode), child) {
		if (!strcmp(child->schema->name, "group-nve-group"))
			vty_out(vty, " vnc export bgp group-nve group %s\n", lyd_get_value(child));
	}
	if (yang_dnode_exists(dnode, "ipv4-prefix-list"))
		vty_out(vty, " vnc export bgp ipv4 prefix-list %s\n",
			yang_dnode_get_string(dnode, "ipv4-prefix-list"));
	if (yang_dnode_exists(dnode, "ipv6-prefix-list"))
		vty_out(vty, " vnc export bgp ipv6 prefix-list %s\n",
			yang_dnode_get_string(dnode, "ipv6-prefix-list"));
	if (yang_dnode_exists(dnode, "route-map"))
		vty_out(vty, " vnc export bgp route-map %s\n",
			yang_dnode_get_string(dnode, "route-map"));
}

void vnc_export_zebra_cli_show(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const struct lyd_node *child;
	const char *mode;

	if (yang_dnode_exists(dnode, "mode")) {
		mode = yang_dnode_get_string(dnode, "mode");
		if (strcmp(mode, "none"))
			vty_out(vty, " vnc export zebra mode %s\n", mode);
	}

	LY_LIST_FOR (lyd_child(dnode), child) {
		if (!strcmp(child->schema->name, "group-nve-group"))
			vty_out(vty, " vnc export zebra group-nve group %s\n",
				lyd_get_value(child));
	}

	if (yang_dnode_exists(dnode, "ipv4-prefix-list"))
		vty_out(vty, " vnc export zebra ipv4 prefix-list %s\n",
			yang_dnode_get_string(dnode, "ipv4-prefix-list"));
	if (yang_dnode_exists(dnode, "ipv6-prefix-list"))
		vty_out(vty, " vnc export zebra ipv6 prefix-list %s\n",
			yang_dnode_get_string(dnode, "ipv6-prefix-list"));
	if (yang_dnode_exists(dnode, "route-map"))
		vty_out(vty, " vnc export zebra route-map %s\n",
			yang_dnode_get_string(dnode, "route-map"));
}

void vnc_redistribute_cli_show(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const struct lyd_node *child;
	const char *mode;
	const char *view = NULL;

	if (yang_dnode_exists(dnode, "nve-group"))
		vty_out(vty, " vnc redistribute nve-group %s\n",
			yang_dnode_get_string(dnode, "nve-group"));
	if (yang_dnode_exists(dnode, "lifetime")) {
		const char *lt = yang_dnode_get_string(dnode, "lifetime");

		vty_out(vty, " vnc redistribute lifetime %s\n", lt);
	}
	if (yang_dnode_exists(dnode, "resolve-nve-roo-ec-local-admin")) {
		uint16_t roo = yang_dnode_get_uint16(dnode, "resolve-nve-roo-ec-local-admin");

		if (roo != BGP_VNC_CONFIG_RESOLVE_NVE_ROO_LOCAL_ADMIN_DEFAULT || show_defaults)
			vty_out(vty, " vnc redistribute resolve-nve roo-ec-local-admin %u\n", roo);
	}

	if (yang_dnode_exists(dnode, "mode")) {
		mode = yang_dnode_get_string(dnode, "mode");
		if (strcmp(mode, "plain"))
			vty_out(vty, " vnc redistribute mode %s\n", mode);
	}

	if (yang_dnode_exists(dnode, "bgp-direct-to-nve-groups-view"))
		view = yang_dnode_get_string(dnode, "bgp-direct-to-nve-groups-view");

	if (yang_dnode_exists(dnode, "bgp-direct-ipv4-prefix-list"))
		vty_out(vty, " vnc redistribute bgp-direct ipv4 prefix-list %s\n",
			yang_dnode_get_string(dnode, "bgp-direct-ipv4-prefix-list"));
	if (yang_dnode_exists(dnode, "bgp-direct-ipv6-prefix-list"))
		vty_out(vty, " vnc redistribute bgp-direct ipv6 prefix-list %s\n",
			yang_dnode_get_string(dnode, "bgp-direct-ipv6-prefix-list"));
	if (yang_dnode_exists(dnode, "bgp-direct-to-nve-groups-ipv4-prefix-list"))
		vty_out(vty, " vnc redistribute bgp-direct-to-nve-groups ipv4 prefix-list %s\n",
			yang_dnode_get_string(dnode, "bgp-direct-to-nve-groups-ipv4-prefix-list"));
	if (yang_dnode_exists(dnode, "bgp-direct-to-nve-groups-ipv6-prefix-list"))
		vty_out(vty, " vnc redistribute bgp-direct-to-nve-groups ipv6 prefix-list %s\n",
			yang_dnode_get_string(dnode, "bgp-direct-to-nve-groups-ipv6-prefix-list"));
	if (yang_dnode_exists(dnode, "bgp-direct-route-map"))
		vty_out(vty, " vnc redistribute bgp-direct route-map %s\n",
			yang_dnode_get_string(dnode, "bgp-direct-route-map"));
	if (yang_dnode_exists(dnode, "bgp-direct-to-nve-groups-route-map"))
		vty_out(vty, " vnc redistribute bgp-direct-to-nve-groups route-map %s\n",
			yang_dnode_get_string(dnode, "bgp-direct-to-nve-groups-route-map"));

	/* Emit ipv4-source and ipv6-source entries */
	LY_LIST_FOR (lyd_child(dnode), child) {
		const char *afistr;
		const char *src;

		if (!strcmp(child->schema->name, "ipv4-source"))
			afistr = "ipv4";
		else if (!strcmp(child->schema->name, "ipv6-source"))
			afistr = "ipv6";
		else
			continue;

		src = lyd_get_value(child);
		if (view && !strcmp(src, "bgp-direct-to-nve-groups"))
			vty_out(vty, " vnc redistribute %s %s view %s\n", afistr, src, view);
		else
			vty_out(vty, " vnc redistribute %s %s\n", afistr, src);
	}
}


/* --- redistribute / export prefix-list and route-map filters --- */

DEFPY_YANG(vnc_redist_bgpdirect_prefixlist_cli,
	   vnc_redist_bgpdirect_prefixlist_cli_cmd,
	   "[no] vnc redistribute <bgp-direct|bgp-direct-to-nve-groups>$proto <ipv4|ipv6>$afi prefix-list ![NAME$name]",
	   NO_STR
	   "VNC/RFAPI configuration\n"
	   "Redistribute from other protocol\n"
	   "Redistribute from BGP directly\n"
	   "Redistribute from BGP without Zebra, only to configured NVE groups\n"
	   "IPv4 routes\n"
	   "IPv6 routes\n"
	   "Prefix-list for filtering redistributed routes\n"
	   "Prefix list name\n")
{
	char xpath[XPATH_MAXLEN];

	snprintfrr(xpath, sizeof(xpath), "./frr-bgp-vnc:vnc/redistribute/%s-%s-prefix-list", proto,
		   afi);
	return vnc_cli_filter_apply(vty, xpath, no, name);
}

DEFPY_YANG(vnc_redist_bgpdirect_routemap_cli,
	   vnc_redist_bgpdirect_routemap_cli_cmd,
	   "[no] vnc redistribute <bgp-direct|bgp-direct-to-nve-groups>$proto route-map ![NAME$name]",
	   NO_STR
	   "VNC/RFAPI configuration\n"
	   "Redistribute from other protocols\n"
	   "Redistribute from BGP directly\n"
	   "Redistribute from BGP without Zebra, only to configured NVE groups\n"
	   "Route-map for filtering redistributed routes\n"
	   "Route map name\n")
{
	char xpath[XPATH_MAXLEN];

	snprintfrr(xpath, sizeof(xpath), "./frr-bgp-vnc:vnc/redistribute/%s-route-map", proto);
	return vnc_cli_filter_apply(vty, xpath, no, name);
}

DEFPY_YANG(vnc_nve_export_prefixlist_cli,
	   vnc_nve_export_prefixlist_cli_cmd,
	   "[no] vnc export <bgp|zebra>$proto <ipv4|ipv6>$afi prefix-list ![NAME$name]",
	   NO_STR
	   "VNC/RFAPI configuration\n"
	   "Export to other protocols\n"
	   "Export to BGP\n"
	   "Export to Zebra (experimental)\n"
	   "IPv4 prefixes\n"
	   "IPv6 prefixes\n"
	   "Prefix-list for filtering exported routes\n"
	   "Prefix list name\n")
{
	char xpath[XPATH_MAXLEN];

	snprintfrr(xpath, sizeof(xpath), "./frr-bgp-vnc:vnc/export/%s/%s-prefix-list", proto, afi);
	return vnc_cli_filter_apply(vty, xpath, no, name);
}

DEFPY_YANG(vnc_nve_export_routemap_cli,
	   vnc_nve_export_routemap_cli_cmd,
	   "[no] vnc export <bgp|zebra>$proto route-map ![NAME$name]",
	   NO_STR
	   "VNC/RFAPI configuration\n"
	   "Export to other protocols\n"
	   "Export to BGP\n"
	   "Export to Zebra (experimental)\n"
	   "Route-map for filtering exported routes\n"
	   "Route map name\n")
{
	char xpath[XPATH_MAXLEN];

	snprintfrr(xpath, sizeof(xpath), "./frr-bgp-vnc:vnc/export/%s/route-map", proto);
	return vnc_cli_filter_apply(vty, xpath, no, name);
}

DEFPY_YANG(vnc_nve_group_redist_bgpdirect_prefixlist_cli,
	   vnc_nve_group_redist_bgpdirect_prefixlist_cli_cmd,
	   "[no] redistribute bgp-direct <ipv4|ipv6>$afi prefix-list ![NAME$name]",
	   NO_STR
	   "Redistribute from other protocol\n"
	   "Redistribute from BGP directly\n"
	   "IPv4 routes\n"
	   "IPv6 routes\n"
	   "Prefix-list for filtering redistributed routes\n"
	   "Prefix list name\n")
{
	char xpath[XPATH_MAXLEN];

	snprintfrr(xpath, sizeof(xpath), "./bgp-direct-%s-prefix-list", afi);
	return vnc_cli_filter_apply(vty, xpath, no, name);
}

DEFPY_YANG(vnc_nve_group_redist_bgpdirect_routemap_cli,
	   vnc_nve_group_redist_bgpdirect_routemap_cli_cmd,
	   "[no] redistribute bgp-direct route-map ![NAME$name]",
	   NO_STR
	   "Redistribute from other protocols\n"
	   "Redistribute from BGP directly\n"
	   "Route-map for filtering redistributed routes\n"
	   "Route map name\n")
{
	return vnc_cli_filter_apply(vty, "./bgp-direct-route-map", no, name);
}

DEFPY_YANG(vnc_nve_group_export_prefixlist_cli,
	   vnc_nve_group_export_prefixlist_cli_cmd,
	   "[no] export <bgp|zebra>$proto <ipv4|ipv6>$afi prefix-list ![NAME$name]",
	   NO_STR
	   "Export to other protocols\n"
	   "Export to BGP\n"
	   "Export to Zebra (experimental)\n"
	   "IPv4 routes\n"
	   "IPv6 routes\n"
	   "Prefix-list for filtering exported routes\n"
	   "Prefix list name\n")
{
	char xpath[XPATH_MAXLEN];

	snprintfrr(xpath, sizeof(xpath), "./%s-export-%s-prefix-list", proto, afi);
	return vnc_cli_filter_apply(vty, xpath, no, name);
}

DEFPY_YANG(vnc_nve_group_export_routemap_cli,
	   vnc_nve_group_export_routemap_cli_cmd,
	   "[no] export <bgp|zebra>$proto route-map ![NAME$name]",
	   NO_STR
	   "Export to other protocols\n"
	   "Export to BGP\n"
	   "Export to Zebra (experimental)\n"
	   "Route-map for filtering exported routes\n"
	   "Route map name\n")
{
	char xpath[XPATH_MAXLEN];

	snprintfrr(xpath, sizeof(xpath), "./%s-export-route-map", proto);
	return vnc_cli_filter_apply(vty, xpath, no, name);
}

DEFPY_YANG(vnc_vrf_policy_export_prefixlist_cli,
	   vnc_vrf_policy_export_prefixlist_cli_cmd,
	   "[no] export <ipv4|ipv6>$afi prefix-list ![NAME$name]",
	   NO_STR
	   "Export to VRF\n"
	   "IPv4 routes\n"
	   "IPv6 routes\n"
	   "Prefix-list for filtering exported routes\n"
	   "Prefix list name\n")
{
	char xpath[XPATH_MAXLEN];

	snprintfrr(xpath, sizeof(xpath), "./%s-export-prefix-list", afi);
	return vnc_cli_filter_apply(vty, xpath, no, name);
}

DEFPY_YANG(vnc_vrf_policy_export_routemap_cli,
	   vnc_vrf_policy_export_routemap_cli_cmd,
	   "[no] export route-map ![NAME$name]",
	   NO_STR
	   "Export to VRF\n"
	   "Route-map for filtering exported routes\n"
	   "Route map name\n")
{
	return vnc_cli_filter_apply(vty, "./export-route-map", no, name);
}

/* --- advertise-un-method --- */

DEFPY_YANG(vnc_advertise_un_method_cli, vnc_advertise_un_method_cli_cmd,
	   "vnc advertise-un-method encap-attr$method",
	   "VNC/RFAPI configuration\n"
	   "Method of advertising UN addresses\n"
	   "Via Tunnel Encap attribute (in VPN SAFI)\n")
{
	nb_cli_enqueue_change(vty, "./frr-bgp-vnc:vnc/advertise-un-method", NB_OP_MODIFY, method);
	return nb_cli_apply_changes(vty, NULL);
}

/* --- defaults / nve-group l2rd --- */

DEFPY_YANG(vnc_l2rd_cli, vnc_l2rd_cli_cmd,
	   "[no] l2rd [<(1-255)$val|auto-vn$auto_vn>]",
	   NO_STR
	   "Specify Local Nve ID value to use in RD for L2 routes\n"
	   "Fixed value 1-255\n"
	   "use the low-order octet of the NVE's VN address\n")
{
	if (no) {
		nb_cli_enqueue_change(vty, "./l2rd", NB_OP_DESTROY, NULL);
	} else if (auto_vn) {
		nb_cli_enqueue_change(vty, "./l2rd", NB_OP_MODIFY, "auto-vn");
	} else if (val_str) {
		nb_cli_enqueue_change(vty, "./l2rd", NB_OP_MODIFY, val_str);
	} else {
		vty_out(vty, "%% Missing l2rd value\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	return nb_cli_apply_changes(vty, NULL);
}

/* --- l2-group --- */

DEFPY_YANG_NOSH(vnc_l2_group_cli, vnc_l2_group_cli_cmd,
		"vnc l2-group WORD$name",
		"VNC/RFAPI configuration\n"
		"Configure a L2 group\n"
		"Group name\n")
{
	char xpath[XPATH_MAXLEN];
	char xpath_abs[XPATH_MAXLEN + 256];
	int ret;

	snprintfrr(xpath, sizeof(xpath), "./frr-bgp-vnc:vnc/l2-group[name='%s']", name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	ret = nb_cli_apply_changes_clear_pending(vty, NULL);
	if (ret != CMD_SUCCESS)
		return ret;

	snprintfrr(xpath_abs, sizeof(xpath_abs), "%s/frr-bgp-vnc:vnc/l2-group[name='%s']",
		   VTY_CURR_XPATH, name);
	VTY_PUSH_XPATH(BGP_VNC_L2_GROUP_NODE, xpath_abs);
	return CMD_SUCCESS;
}

DEFPY_YANG(no_vnc_l2_group_cli, no_vnc_l2_group_cli_cmd,
	   "no vnc l2-group WORD$name",
	   NO_STR
	   "VNC/RFAPI configuration\n"
	   "Configure a L2 group\n"
	   "Group name\n")
{
	char xpath[XPATH_MAXLEN];

	snprintfrr(xpath, sizeof(xpath), "./frr-bgp-vnc:vnc/l2-group[name='%s']", name);
	if (!vnc_cli_candidate_get(vty, xpath)) {
		vty_out(vty, "No L2 group named \"%s\"\n", name);
		return CMD_WARNING_CONFIG_FAILED;
	}
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(vnc_l2_group_lni_cli, vnc_l2_group_lni_cli_cmd,
	   "logical-network-id (0-4294967295)$lni",
	   "Specify Logical Network ID associated with group\n"
	   "value\n")
{
	nb_cli_enqueue_change(vty, "./logical-network-id", NB_OP_MODIFY, lni_str);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(vnc_l2_group_labels_cli, vnc_l2_group_labels_cli_cmd,
	   "[no] labels (0-1048575)...",
	   NO_STR
	   "Specify label values associated with group\n"
	   "Space separated list of label values <0-1048575>\n")
{
	int idx = 0;
	int i;
	char xpath[XPATH_MAXLEN];
	const struct lyd_node *group = NULL;

	/* running-config prints every label on one line. Accept that line back. */
	if (!argv_find(argv, argc, "(0-1048575)", &idx)) {
		vty_out(vty, "%% Missing label\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (vty->candidate_config && vty->candidate_config->dnode)
		group = yang_dnode_get(vty->candidate_config->dnode, VTY_CURR_XPATH);

	for (i = idx; i < argc; i++) {
		bool exists;

		snprintfrr(xpath, sizeof(xpath), "./labels[.='%s']", argv[i]->arg);
		exists = group && yang_dnode_exists(group, xpath);
		if (no) {
			if (exists)
				nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
		} else if (!exists) {
			nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
		}
	}
	return nb_cli_apply_changes(vty, NULL);
}

void vnc_advertise_un_method_cli_show(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults)
{
	const char *method = yang_dnode_get_string(dnode, NULL);

	/* Classic write only emits when encap-safi is configured. */
	(void)vty;
	(void)dnode;
	(void)show_defaults;
	(void)method;
}

void vnc_l2_group_cli_show(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const struct lyd_node *child;
	const char *name = yang_dnode_get_string(dnode, "name");
	struct bgp *bgp = bgp_nb_vnc_get_bgp(dnode);
	struct rfapi_l2_group_cfg *rfgc = nb_running_get_entry_non_rec(dnode, NULL, false);

	vty_out(vty, " vnc l2-group %s\n", name);
	if (yang_dnode_exists(dnode, "logical-network-id") &&
	    yang_dnode_get_uint32(dnode, "logical-network-id") != 0)
		vty_out(vty, "  logical-network-id %u\n",
			yang_dnode_get_uint32(dnode, "logical-network-id"));

	{
		bool first = true;

		LY_LIST_FOR (lyd_child(dnode), child) {
			if (strcmp(child->schema->name, "labels"))
				continue;
			if (first) {
				vty_out(vty, "  labels");
				first = false;
			}
			vty_out(vty, " %s", lyd_get_value(child));
		}
		if (!first)
			vty_out(vty, "\n");
	}
	vnc_rt_cli_show_helper(vty, dnode, "  ");
	if (bgp && bgp->rfapi && bgp->rfapi->rfp_methods.cfg_group_cb)
		bgp->rfapi->rfp_methods.cfg_group_cb(vty, bgp->rfapi->rfp,
						     RFAPI_RFP_CFG_GROUP_L2, name,
						     rfgc ? rfgc->rfp_cfg : NULL);
}

void vnc_l2_group_cli_show_end(struct vty *vty, const struct lyd_node *dnode)
{
	vty_out(vty, "  exit-vnc\n");
}


void bgp_vnc_cli_init(void)
{
	/*
	 * Register VNC/VRF-policy cmd_nodes before install_element().
	 * bgp_vty_init() → bgp_cli_init() runs before rfapi_init(), so
	 * nodes must be installed here rather than from rfapi_init().
	 */
	bgp_rfapi_cfg_init();

	install_element(BGP_NODE, &vnc_defaults_cli_cmd);
	install_element(BGP_NODE, &vnc_nve_group_cli_cmd);
	install_element(BGP_NODE, &no_vnc_nve_group_cli_cmd);
	install_element(BGP_NODE, &vrf_policy_cli_cmd);
	install_element(BGP_NODE, &no_vrf_policy_cli_cmd);
	install_element(BGP_NODE, &vnc_l2_group_cli_cmd);
	install_element(BGP_NODE, &no_vnc_l2_group_cli_cmd);
	install_element(BGP_NODE, &vnc_advertise_un_method_cli_cmd);
	install_element(BGP_NODE, &vnc_export_bgp_mode_cli_cmd);
	install_element(BGP_NODE, &vnc_export_bgp_group_nve_cli_cmd);
	install_element(BGP_NODE, &no_vnc_export_bgp_group_nve_cli_cmd);
	install_element(BGP_NODE, &vnc_export_bgp_group_nve_no_group_cmd);
	install_element(BGP_NODE, &vnc_export_zebra_mode_cli_cmd);
	install_element(BGP_NODE, &vnc_export_zebra_group_nve_cli_cmd);
	install_element(BGP_NODE, &no_vnc_export_zebra_group_nve_cli_cmd);
	install_element(BGP_NODE, &vnc_export_zebra_group_nve_no_group_cmd);
	install_element(BGP_NODE, &vnc_redistribute_mode_cli_cmd);
	install_element(BGP_NODE, &vnc_redistribute_source_cli_cmd);
	install_element(BGP_NODE, &no_vnc_redistribute_source_cli_cmd);
	install_element(BGP_NODE, &vnc_redistribute_nvegroup_cli_cmd);
	install_element(BGP_NODE, &vnc_redistribute_lifetime_cli_cmd);
	install_element(BGP_NODE, &vnc_redistribute_rh_roo_localadmin_cli_cmd);
	install_element(BGP_NODE, &vnc_redistribute_bgp_exterior_cli_cmd);
	install_element(BGP_NODE, &vnc_redist_bgpdirect_prefixlist_cli_cmd);
	install_element(BGP_NODE, &vnc_redist_bgpdirect_routemap_cli_cmd);
	install_element(BGP_NODE, &vnc_nve_export_prefixlist_cli_cmd);
	install_element(BGP_NODE, &vnc_nve_export_routemap_cli_cmd);
	install_element(BGP_NODE, &rfp_holddown_factor_cli_cmd);
	install_element(BGP_NODE, &rfp_full_table_download_cli_cmd);

	install_element(BGP_VNC_DEFAULTS_NODE, &vnc_defaults_rd_cli_cmd);
	install_element(BGP_VNC_DEFAULTS_NODE, &vnc_defaults_response_lifetime_cli_cmd);
	install_element(BGP_VNC_DEFAULTS_NODE, &vnc_l2rd_cli_cmd);
	install_element(BGP_VNC_DEFAULTS_NODE, &vnc_rt_cli_cmd);
	install_element(BGP_VNC_DEFAULTS_NODE, &exit_vnc_cli_cmd);

	install_element(BGP_VNC_NVE_GROUP_NODE, &vnc_nve_group_prefix_cli_cmd);
	install_element(BGP_VNC_NVE_GROUP_NODE, &vnc_nve_group_rd_cli_cmd);
	install_element(BGP_VNC_NVE_GROUP_NODE, &vnc_nve_group_response_lifetime_cli_cmd);
	install_element(BGP_VNC_NVE_GROUP_NODE, &vnc_l2rd_cli_cmd);
	install_element(BGP_VNC_NVE_GROUP_NODE, &vnc_rt_cli_cmd);
	install_element(BGP_VNC_NVE_GROUP_NODE, &vnc_nve_group_redist_bgpdirect_prefixlist_cli_cmd);
	install_element(BGP_VNC_NVE_GROUP_NODE, &vnc_nve_group_redist_bgpdirect_routemap_cli_cmd);
	install_element(BGP_VNC_NVE_GROUP_NODE, &vnc_nve_group_export_prefixlist_cli_cmd);
	install_element(BGP_VNC_NVE_GROUP_NODE, &vnc_nve_group_export_routemap_cli_cmd);
	install_element(BGP_VNC_NVE_GROUP_NODE, &exit_vnc_cli_cmd);

	install_element(BGP_VRF_POLICY_NODE, &vrf_policy_label_cli_cmd);
	install_element(BGP_VRF_POLICY_NODE, &vrf_policy_rd_cli_cmd);
	install_element(BGP_VRF_POLICY_NODE, &vnc_rt_cli_cmd);
	install_element(BGP_VRF_POLICY_NODE, &vrf_policy_nexthop_cli_cmd);
	install_element(BGP_VRF_POLICY_NODE, &vnc_vrf_policy_export_prefixlist_cli_cmd);
	install_element(BGP_VRF_POLICY_NODE, &vnc_vrf_policy_export_routemap_cli_cmd);
	install_element(BGP_VRF_POLICY_NODE, &exit_vrf_policy_cli_cmd);

	install_element(BGP_VNC_L2_GROUP_NODE, &vnc_l2_group_lni_cli_cmd);
	install_element(BGP_VNC_L2_GROUP_NODE, &vnc_l2_group_labels_cli_cmd);
	install_element(BGP_VNC_L2_GROUP_NODE, &vnc_rt_cli_cmd);
	install_element(BGP_VNC_L2_GROUP_NODE, &exit_vnc_cli_cmd);
}

#endif /* ENABLE_BGP_VNC */
