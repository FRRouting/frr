// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP YANG-backed CLI (northbound conversion)
 * Copyright (C) 2026 FRRouting
 */

#include <zebra.h>

#include "command.h"
#include "northbound_cli.h"
#include "vrf.h"
#include "asn.h"
#include "routing_nb.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_nb.h"

/*
 * control-plane-protocol keys: type, name, vrf
 * BGP container is under frr-bgp:bgp
 */
#define BGP_CPP_XPATH                                                                             \
	"/frr-routing:routing/control-plane-protocols/control-plane-protocol[type='frr-bgp:bgp'][name='%s'][vrf='%s']"
#define BGP_BASE_XPATH BGP_CPP_XPATH "/frr-bgp:bgp"

/*
 * router bgp — create/enter instance via YANG
 */
DEFUN_YANG_NOSH(router_bgp_yang, router_bgp_yang_cmd,
		"router bgp [ASNUM [<view|vrf> VIEWVRFNAME] [as-notation <dot|dot+|plain>]]",
		ROUTER_STR BGP_STR AS_STR BGP_INSTANCE_HELP_STR
		"Force the AS notation output\n"
		"use 'AA.BB' format for AS 4 byte values\n"
		"use 'AA.BB' format for all AS values\n"
		"use plain format for all AS values\n")
{
	char cpp_xpath[XPATH_MAXLEN];
	char bgp_xpath[XPATH_MAXLEN];
	char leaf_xpath[XPATH_MAXLEN + 256];
	int ret;
	as_t as = 0;
	const char *name = VRF_DEFAULT_NAME;
	const char *vrf_name = VRF_DEFAULT_NAME;
	bool is_view = false;
	enum asnotation_mode asnotation = ASNOTATION_UNDEFINED;
	int idx = 0;

	/* "router bgp" with no ASN — enter the sole existing instance */
	if (argc == 2) {
		struct bgp *bgp = bgp_get_default();

		if (!bgp) {
			vty_out(vty, "%% No BGP process is configured\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		if (listcount(bm->bgp) > 1) {
			vty_out(vty, "%% Please specify ASN and VRF\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		if (bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT) {
			name = VRF_DEFAULT_NAME;
			vrf_name = VRF_DEFAULT_NAME;
		} else {
			name = bgp->name;
			vrf_name = bgp->name;
			is_view = (bgp->inst_type == BGP_INSTANCE_TYPE_VIEW);
		}

		snprintfrr(bgp_xpath, sizeof(bgp_xpath), BGP_BASE_XPATH, name, vrf_name);
		VTY_PUSH_XPATH(BGP_NODE, bgp_xpath);
		VTY_PUSH_CONTEXT(BGP_NODE, bgp);
		return CMD_SUCCESS;
	}

	if (!asn_str2asn(argv[2]->arg, &as)) {
		vty_out(vty, "%% BGP: No such AS %s\n", argv[2]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (argv_find(argv, argc, "VIEWVRFNAME", &idx)) {
		name = argv[idx]->arg;
		vrf_name = name;
		if (strmatch(argv[idx - 1]->text, "view"))
			is_view = true;
		if (strmatch(name, VRF_DEFAULT_NAME)) {
			name = VRF_DEFAULT_NAME;
			vrf_name = VRF_DEFAULT_NAME;
		}
	}

	idx = 0;
	if (argv_find(argv, argc, "as-notation", &idx)) {
		if (strmatch(argv[idx + 1]->text, "dot+"))
			asnotation = ASNOTATION_DOTPLUS;
		else if (strmatch(argv[idx + 1]->text, "dot"))
			asnotation = ASNOTATION_DOT;
		else
			asnotation = ASNOTATION_PLAIN;
	}

	snprintfrr(cpp_xpath, sizeof(cpp_xpath), BGP_CPP_XPATH, name, vrf_name);
	snprintfrr(bgp_xpath, sizeof(bgp_xpath), BGP_BASE_XPATH, name, vrf_name);

	nb_cli_enqueue_change(vty, cpp_xpath, NB_OP_CREATE, NULL);

	snprintfrr(leaf_xpath, sizeof(leaf_xpath), "%s/global/instance-type-view", bgp_xpath);
	nb_cli_enqueue_change(vty, leaf_xpath, NB_OP_MODIFY, is_view ? "true" : "false");

	snprintfrr(leaf_xpath, sizeof(leaf_xpath), "%s/global/local-as", bgp_xpath);
	nb_cli_enqueue_change(vty, leaf_xpath, NB_OP_MODIFY, asn_asn2asplain(as));

	if (asnotation == ASNOTATION_DOT || asnotation == ASNOTATION_DOTPLUS) {
		snprintfrr(leaf_xpath, sizeof(leaf_xpath), "%s/global/as-notation", bgp_xpath);
		nb_cli_enqueue_change(vty, leaf_xpath, NB_OP_MODIFY,
				      asnotation == ASNOTATION_DOTPLUS ? "dot+" : "dot");
	}

	ret = nb_cli_apply_changes(vty, NULL);
	if (ret == CMD_SUCCESS) {
		struct bgp *bgp;

		VTY_PUSH_XPATH(BGP_NODE, bgp_xpath);

		/* Classic DEFUN children still use VTY_GET_CONTEXT(bgp). */
		if (strmatch(vrf_name, VRF_DEFAULT_NAME))
			bgp = bgp_get_default();
		else
			bgp = bgp_lookup_by_name(name);
		if (bgp)
			VTY_PUSH_CONTEXT(BGP_NODE, bgp);
	}

	return ret;
}

/*
 * Classic no_router_bgp refuses to tear the instance down when an L3VNI is
 * still configured, or when another VRF still imports or exports VPN routes
 * through the default instance. Deleting anyway frees the parent dests while
 * those VRFs still hold vrfleak parent pointers, and the next zebra announce
 * crashes in is_route_parent_evpn().
 */
static bool bgp_cli_vrf_blocks_default_delete(struct bgp *bgp, struct bgp *vrf)
{
	if (CHECK_FLAG(vrf->af_flags[AFI_IP][SAFI_UNICAST], BGP_CONFIG_MPLSVPN_TO_VRF_IMPORT) ||
	    CHECK_FLAG(vrf->af_flags[AFI_IP6][SAFI_UNICAST], BGP_CONFIG_MPLSVPN_TO_VRF_IMPORT) ||
	    CHECK_FLAG(vrf->af_flags[AFI_IP][SAFI_UNICAST], BGP_CONFIG_VRF_TO_MPLSVPN_EXPORT) ||
	    CHECK_FLAG(vrf->af_flags[AFI_IP6][SAFI_UNICAST], BGP_CONFIG_VRF_TO_MPLSVPN_EXPORT) ||
	    CHECK_FLAG(vrf->af_flags[AFI_IP][SAFI_UNICAST], BGP_CONFIG_VRF_TO_VRF_EXPORT) ||
	    CHECK_FLAG(vrf->af_flags[AFI_IP6][SAFI_UNICAST], BGP_CONFIG_VRF_TO_VRF_EXPORT) ||
	    (bgp == bgp_get_evpn() &&
	     (CHECK_FLAG(vrf->af_flags[AFI_L2VPN][SAFI_EVPN], BGP_L2VPN_EVPN_ADV_IPV4_UNICAST) ||
	      CHECK_FLAG(vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
			 BGP_L2VPN_EVPN_ADV_IPV4_UNICAST_GW_IP) ||
	      CHECK_FLAG(vrf->af_flags[AFI_L2VPN][SAFI_EVPN], BGP_L2VPN_EVPN_ADV_IPV6_UNICAST) ||
	      CHECK_FLAG(vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
			 BGP_L2VPN_EVPN_ADV_IPV6_UNICAST_GW_IP))) ||
	    vrf->l3vni)
		return true;
	return false;
}

static bool bgp_cli_no_router_blocked(struct vty *vty, int argc, struct cmd_token **argv)
{
	struct bgp *bgp;
	struct listnode *node, *nnode;
	struct bgp *tmp_bgp;
	const char *name = NULL;
	as_t as = 0;
	int idx = 0;

	if (argc == 3) {
		bgp = bgp_get_default();
		if (!bgp) {
			vty_out(vty, "%% No BGP process is configured\n");
			return true;
		}
		if (listcount(bm->bgp) > 1) {
			vty_out(vty, "%% Please specify ASN and VRF\n");
			return true;
		}
	} else {
		if (!asn_str2asn(argv[3]->arg, &as)) {
			vty_out(vty, "%% BGP: No such AS %s\n", argv[3]->arg);
			return true;
		}
		if (argv_find(argv, argc, "VIEWVRFNAME", &idx)) {
			name = argv[idx]->arg;
			if (strmatch(argv[idx - 1]->text, "vrf") &&
			    strmatch(name, VRF_DEFAULT_NAME))
				name = NULL;
		}
		bgp = bgp_lookup(as, name);
		if (!bgp) {
			vty_out(vty, "%% Can't find BGP instance\n");
			return true;
		}
	}

	if (bgp->l3vni) {
		vty_out(vty, "%% Please unconfigure l3vni %u\n", bgp->l3vni);
		return true;
	}

	if (bgp->inst_type != BGP_INSTANCE_TYPE_DEFAULT)
		return false;

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, tmp_bgp)) {
		if (tmp_bgp->inst_type != BGP_INSTANCE_TYPE_VRF)
			continue;
		if (CHECK_FLAG(tmp_bgp->vrf_flags, BGP_VRF_AUTO)) {
			bgp_delete(tmp_bgp);
			continue;
		}
		if (bgp_cli_vrf_blocks_default_delete(bgp, tmp_bgp)) {
			vty_out(vty,
				"%% Cannot delete default BGP instance. Dependent VRF instances exist\n");
			return true;
		}
	}
	return false;
}

DEFUN_YANG(no_router_bgp_yang, no_router_bgp_yang_cmd,
	   "no router bgp [ASNUM [<view|vrf> VIEWVRFNAME]]",
	   NO_STR ROUTER_STR BGP_STR AS_STR BGP_INSTANCE_HELP_STR)
{
	char cpp_xpath[XPATH_MAXLEN];
	const char *name = VRF_DEFAULT_NAME;
	const char *vrf_name = VRF_DEFAULT_NAME;
	int idx = 0;

	if (argv_find(argv, argc, "VIEWVRFNAME", &idx)) {
		name = argv[idx]->arg;
		vrf_name = name;
		if (strmatch(name, VRF_DEFAULT_NAME)) {
			name = VRF_DEFAULT_NAME;
			vrf_name = VRF_DEFAULT_NAME;
		}
	} else if (argc == 3) {
		/* no router bgp — delete default instance */
		name = VRF_DEFAULT_NAME;
		vrf_name = VRF_DEFAULT_NAME;
	}

	if (bgp_cli_no_router_blocked(vty, argc, argv))
		return CMD_WARNING_CONFIG_FAILED;

	snprintfrr(cpp_xpath, sizeof(cpp_xpath), BGP_CPP_XPATH, name, vrf_name);
	nb_cli_enqueue_change(vty, cpp_xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes_clear_pending(vty, NULL);
}

DEFUN_YANG(bgp_router_id_yang, bgp_router_id_yang_cmd,
	   "bgp router-id A.B.C.D",
	   BGP_STR
	   "Override configured router identifier\n"
	   "Manually configured router identifier\n")
{
	nb_cli_enqueue_change(vty, "./global/router-id", NB_OP_MODIFY, argv[2]->arg);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_router_id_yang, no_bgp_router_id_yang_cmd,
	   "no bgp router-id [A.B.C.D]",
	   NO_STR BGP_STR
	   "Override configured router identifier\n"
	   "Manually configured router identifier\n")
{
	nb_cli_enqueue_change(vty, "./global/router-id", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(bgp_log_neighbor_changes_yang, bgp_log_neighbor_changes_yang_cmd,
	   "bgp log-neighbor-changes",
	   BGP_STR "Log neighbor up/down and reset reason\n")
{
	nb_cli_enqueue_change(vty, "./global/global-neighbor-config/log-neighbor-changes",
			      NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_log_neighbor_changes_yang,
	   no_bgp_log_neighbor_changes_yang_cmd,
	   "no bgp log-neighbor-changes",
	   NO_STR BGP_STR "Log neighbor up/down and reset reason\n")
{
	struct bgp *bgp = VTY_GET_CONTEXT(bgp);
	int ret;

	nb_cli_enqueue_change(vty, "./global/global-neighbor-config/log-neighbor-changes",
			      NB_OP_MODIFY, "false");
	ret = nb_cli_apply_changes(vty, NULL);
	/*
	 * Datacenter enables logging in bgp_get_vty() while the YANG default
	 * stays false, so this modify is not a diff and the callback never
	 * clears the flag. A config-file batch commits later; create applies
	 * an explicit false from that candidate.
	 */
	if (ret == CMD_SUCCESS && bgp && !vty->pending_commit)
		UNSET_FLAG(bgp->flags, BGP_FLAG_LOG_NEIGHBOR_CHANGES);
	return ret;
}

DEFUN_YANG(bgp_ebgp_requires_policy_yang, bgp_ebgp_requires_policy_yang_cmd,
	   "bgp ebgp-requires-policy",
	   BGP_STR "Require in and out policy for eBGP peers (RFC8212)\n")
{
	nb_cli_enqueue_change(vty, "./global/ebgp-requires-policy", NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_ebgp_requires_policy_yang,
	   no_bgp_ebgp_requires_policy_yang_cmd,
	   "no bgp ebgp-requires-policy",
	   NO_STR BGP_STR
	   "Require in and out policy for eBGP peers (RFC8212)\n")
{
	nb_cli_enqueue_change(vty, "./global/ebgp-requires-policy", NB_OP_MODIFY, "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(bgp_network_import_check_yang, bgp_network_import_check_yang_cmd,
	   "bgp network import-check",
	   BGP_STR
	   "BGP network command\n"
	   "Check BGP network route exists in IGP\n")
{
	nb_cli_enqueue_change(vty, "./global/import-check", NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_network_import_check_yang,
	   no_bgp_network_import_check_yang_cmd,
	   "no bgp network import-check",
	   NO_STR BGP_STR
	   "BGP network command\n"
	   "Check BGP network route exists in IGP\n")
{
	nb_cli_enqueue_change(vty, "./global/import-check", NB_OP_MODIFY, "false");
	return nb_cli_apply_changes(vty, NULL);
}

void bgp_cli_init(void)
{
	install_element(CONFIG_NODE, &router_bgp_yang_cmd);
	install_element(CONFIG_NODE, &no_router_bgp_yang_cmd);

	install_element(BGP_NODE, &bgp_router_id_yang_cmd);
	install_element(BGP_NODE, &no_bgp_router_id_yang_cmd);
	install_element(BGP_NODE, &bgp_log_neighbor_changes_yang_cmd);
	install_element(BGP_NODE, &no_bgp_log_neighbor_changes_yang_cmd);
	install_element(BGP_NODE, &bgp_ebgp_requires_policy_yang_cmd);
	install_element(BGP_NODE, &no_bgp_ebgp_requires_policy_yang_cmd);
	install_element(BGP_NODE, &bgp_network_import_check_yang_cmd);
	install_element(BGP_NODE, &no_bgp_network_import_check_yang_cmd);
}
