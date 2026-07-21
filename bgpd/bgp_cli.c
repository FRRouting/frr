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
#include "frrstr.h"
#include "bfd.h"
#include "routing_nb.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_nb.h"
#include "bgpd/bgp_io.h"
#include "bgpd/bgp_updgrp.h"
#include "bgpd/bgp_zebra.h"

#include "bgpd/bgp_cli_clippy.c"

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
	if (argc == 4) {
		struct in_addr req_id = {};
		struct in_addr cur_id = {};
		char xpath[XPATH_MAXLEN];

		if (inet_pton(AF_INET, argv[3]->arg, &req_id) != 1)
			return CMD_WARNING_CONFIG_FAILED;

		snprintfrr(xpath, sizeof(xpath), "%s/global/router-id", VTY_CURR_XPATH);
		if (yang_dnode_exists(vty->candidate_config->dnode, xpath))
			yang_dnode_get_ipv4(&cur_id, vty->candidate_config->dnode, "%s", xpath);

		if (!IPV4_ADDR_SAME(&cur_id, &req_id)) {
			vty_out(vty, "%% BGP router-id doesn't match\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

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

DEFUN_YANG(bgp_cluster_id_yang, bgp_cluster_id_yang_cmd,
	   "bgp cluster-id <A.B.C.D|(1-4294967295)>",
	   BGP_STR
	   "Configure Route-Reflector Cluster-id\n"
	   "Route-Reflector Cluster-id in IP address format\n"
	   "Route-Reflector Cluster-id as 32 bit quantity\n")
{
	nb_cli_enqueue_change(vty, "./global/route-reflector/route-reflector-cluster-id",
			      NB_OP_MODIFY, argv[2]->arg);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_cluster_id_yang, no_bgp_cluster_id_yang_cmd,
	   "no bgp cluster-id [<A.B.C.D|(1-4294967295)>]",
	   NO_STR BGP_STR
	   "Configure Route-Reflector Cluster-id\n"
	   "Route-Reflector Cluster-id in IP address format\n"
	   "Route-Reflector Cluster-id as 32 bit quantity\n")
{
	nb_cli_enqueue_change(vty, "./global/route-reflector/route-reflector-cluster-id",
			      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(bgp_client_to_client_reflection_yang,
	   bgp_client_to_client_reflection_yang_cmd,
	   "bgp client-to-client reflection",
	   BGP_STR
	   "Configure client to client route reflection\n"
	   "reflection of routes allowed\n")
{
	nb_cli_enqueue_change(vty, "./global/route-reflector/no-client-reflect", NB_OP_MODIFY,
			      "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_client_to_client_reflection_yang,
	   no_bgp_client_to_client_reflection_yang_cmd,
	   "no bgp client-to-client reflection",
	   NO_STR BGP_STR
	   "Configure client to client route reflection\n"
	   "reflection of routes allowed\n")
{
	nb_cli_enqueue_change(vty, "./global/route-reflector/no-client-reflect", NB_OP_MODIFY,
			      "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(bgp_always_compare_med_yang, bgp_always_compare_med_yang_cmd,
	   "bgp always-compare-med",
	   BGP_STR "Allow comparing MED from different neighbors\n")
{
	nb_cli_enqueue_change(vty, "./global/route-selection-options/always-compare-med",
			      NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_always_compare_med_yang, no_bgp_always_compare_med_yang_cmd,
	   "no bgp always-compare-med",
	   NO_STR BGP_STR
	   "Allow comparing MED from different neighbors\n")
{
	nb_cli_enqueue_change(vty, "./global/route-selection-options/always-compare-med",
			      NB_OP_MODIFY, "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(bgp_deterministic_med_yang, bgp_deterministic_med_yang_cmd,
	   "bgp deterministic-med",
	   BGP_STR
	   "Pick the best-MED path among paths advertised from the neighboring AS\n")
{
	nb_cli_enqueue_change(vty, "./global/route-selection-options/deterministic-med",
			      NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_deterministic_med_yang, no_bgp_deterministic_med_yang_cmd,
	   "no bgp deterministic-med",
	   NO_STR BGP_STR
	   "Pick the best-MED path among paths advertised from the neighboring AS\n")
{
	nb_cli_enqueue_change(vty, "./global/route-selection-options/deterministic-med",
			      NB_OP_MODIFY, "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(bgp_default_local_preference_yang,
	   bgp_default_local_preference_yang_cmd,
	   "bgp default local-preference (0-4294967295)",
	   BGP_STR
	   "Configure BGP defaults\n"
	   "local preference (higher=more preferred)\n"
	   "Configure default local preference value\n")
{
	nb_cli_enqueue_change(vty, "./global/local-pref", NB_OP_MODIFY, argv[3]->arg);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_default_local_preference_yang,
	   no_bgp_default_local_preference_yang_cmd,
	   "no bgp default local-preference [(0-4294967295)]",
	   NO_STR BGP_STR
	   "Configure BGP defaults\n"
	   "local preference (higher=more preferred)\n"
	   "Configure default local preference value\n")
{
	nb_cli_enqueue_change(vty, "./global/local-pref", NB_OP_MODIFY, "100");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(bgp_fast_external_failover_yang, bgp_fast_external_failover_yang_cmd,
	   "bgp fast-external-failover",
	   BGP_STR
	   "Immediately reset session if a link to a directly connected external peer goes down\n")
{
	nb_cli_enqueue_change(vty, "./global/fast-external-failover", NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_fast_external_failover_yang,
	   no_bgp_fast_external_failover_yang_cmd,
	   "no bgp fast-external-failover",
	   NO_STR BGP_STR
	   "Immediately reset session if a link to a directly connected external peer goes down\n")
{
	nb_cli_enqueue_change(vty, "./global/fast-external-failover", NB_OP_MODIFY, "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(bgp_suppress_duplicates_yang, bgp_suppress_duplicates_yang_cmd,
	   "bgp suppress-duplicates",
	   BGP_STR
	   "Suppress duplicate updates if the route actually not changed\n")
{
	nb_cli_enqueue_change(vty, "./global/suppress-duplicates", NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_suppress_duplicates_yang,
	   no_bgp_suppress_duplicates_yang_cmd,
	   "no bgp suppress-duplicates",
	   NO_STR BGP_STR
	   "Suppress duplicate updates if the route actually not changed\n")
{
	nb_cli_enqueue_change(vty, "./global/suppress-duplicates", NB_OP_MODIFY, "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(bgp_graceful_shutdown_yang, bgp_graceful_shutdown_yang_cmd,
	   "bgp graceful-shutdown", BGP_STR "Graceful shutdown parameters\n")
{
	nb_cli_enqueue_change(vty, "./global/graceful-shutdown/enable", NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_graceful_shutdown_yang, no_bgp_graceful_shutdown_yang_cmd,
	   "no bgp graceful-shutdown",
	   NO_STR BGP_STR "Graceful shutdown parameters\n")
{
	nb_cli_enqueue_change(vty, "./global/graceful-shutdown/enable", NB_OP_MODIFY, "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(bgp_reject_as_sets_yang, bgp_reject_as_sets_yang_cmd,
	   "bgp reject-as-sets",
	   BGP_STR
	   "Reject routes with AS_SET or AS_CONFED_SET flag\n")
{
	nb_cli_enqueue_change(vty, "./global/reject-as-sets", NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_reject_as_sets_yang, no_bgp_reject_as_sets_yang_cmd,
	   "no bgp reject-as-sets",
	   NO_STR BGP_STR
	   "Reject routes with AS_SET or AS_CONFED_SET flag\n")
{
	nb_cli_enqueue_change(vty, "./global/reject-as-sets", NB_OP_MODIFY, "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_enforce_first_as_yang, bgp_enforce_first_as_yang_cmd,
	   "[no] bgp enforce-first-as",
	   NO_STR BGP_STR
	   "Enforce the first AS for EBGP routes\n")
{
	nb_cli_enqueue_change(vty, "./global/enforce-first-as", NB_OP_MODIFY,
			      no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(bgp_disable_connected_route_check_yang,
	   bgp_disable_connected_route_check_yang_cmd,
	   "bgp disable-ebgp-connected-route-check",
	   BGP_STR
	   "Disable checking if nexthop is connected on ebgp sessions\n")
{
	nb_cli_enqueue_change(vty, "./global/ebgp-multihop-connected-route-check", NB_OP_MODIFY,
			      "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_disable_connected_route_check_yang,
	   no_bgp_disable_connected_route_check_yang_cmd,
	   "no bgp disable-ebgp-connected-route-check",
	   NO_STR BGP_STR
	   "Disable checking if nexthop is connected on ebgp sessions\n")
{
	nb_cli_enqueue_change(vty, "./global/ebgp-multihop-connected-route-check", NB_OP_MODIFY,
			      "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(bgp_rr_allow_outbound_policy_yang,
	   bgp_rr_allow_outbound_policy_yang_cmd,
	   "bgp route-reflector allow-outbound-policy",
	   BGP_STR
	   "Allow modifications made by out route-map\n"
	   "on ibgp neighbors\n")
{
	nb_cli_enqueue_change(vty, "./global/route-reflector/allow-outbound-policy", NB_OP_MODIFY,
			      "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_rr_allow_outbound_policy_yang,
	   no_bgp_rr_allow_outbound_policy_yang_cmd,
	   "no bgp route-reflector allow-outbound-policy",
	   NO_STR BGP_STR
	   "Allow modifications made by out route-map\n"
	   "on ibgp neighbors\n")
{
	nb_cli_enqueue_change(vty, "./global/route-reflector/allow-outbound-policy", NB_OP_MODIFY,
			      "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_administrative_reset_yang, bgp_administrative_reset_yang_cmd,
	   "[no] bgp hard-administrative-reset",
	   NO_STR BGP_STR
	   "Send Hard Reset CEASE Notification for 'Administrative Reset'\n")
{
	nb_cli_enqueue_change(vty, "./global/hard-administrative-reset", NB_OP_MODIFY,
			      no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(bgp_default_show_hostname_yang, bgp_default_show_hostname_yang_cmd,
	   "bgp default show-hostname",
	   BGP_STR
	   "Configure BGP defaults\n"
	   "Show hostname in certain command outputs\n")
{
	nb_cli_enqueue_change(vty, "./global/show-hostname", NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_default_show_hostname_yang,
	   no_bgp_default_show_hostname_yang_cmd,
	   "no bgp default show-hostname",
	   NO_STR BGP_STR
	   "Configure BGP defaults\n"
	   "Show hostname in certain command outputs\n")
{
	nb_cli_enqueue_change(vty, "./global/show-hostname", NB_OP_MODIFY, "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(bgp_default_show_nexthop_hostname_yang,
	   bgp_default_show_nexthop_hostname_yang_cmd,
	   "bgp default show-nexthop-hostname",
	   BGP_STR
	   "Configure BGP defaults\n"
	   "Show hostname for nexthop in certain command outputs\n")
{
	nb_cli_enqueue_change(vty, "./global/show-nexthop-hostname", NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_default_show_nexthop_hostname_yang,
	   no_bgp_default_show_nexthop_hostname_yang_cmd,
	   "no bgp default show-nexthop-hostname",
	   NO_STR BGP_STR
	   "Configure BGP defaults\n"
	   "Show hostname for nexthop in certain command outputs\n")
{
	nb_cli_enqueue_change(vty, "./global/show-nexthop-hostname", NB_OP_MODIFY, "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(bgp_bestpath_compare_router_id_yang,
	   bgp_bestpath_compare_router_id_yang_cmd,
	   "bgp bestpath compare-routerid",
	   BGP_STR
	   "Change the default bestpath selection\n"
	   "Compare router-id for identical EBGP paths\n")
{
	nb_cli_enqueue_change(vty, "./global/route-selection-options/external-compare-router-id",
			      NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_bestpath_compare_router_id_yang,
	   no_bgp_bestpath_compare_router_id_yang_cmd,
	   "no bgp bestpath compare-routerid",
	   NO_STR BGP_STR
	   "Change the default bestpath selection\n"
	   "Compare router-id for identical EBGP paths\n")
{
	nb_cli_enqueue_change(vty, "./global/route-selection-options/external-compare-router-id",
			      NB_OP_MODIFY, "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(bgp_bestpath_aspath_ignore_yang, bgp_bestpath_aspath_ignore_yang_cmd,
	   "bgp bestpath as-path ignore",
	   BGP_STR
	   "Change the default bestpath selection\n"
	   "AS-path attribute\n"
	   "Ignore as-path length in selecting a route\n")
{
	nb_cli_enqueue_change(vty, "./global/route-selection-options/ignore-as-path-length",
			      NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_bestpath_aspath_ignore_yang,
	   no_bgp_bestpath_aspath_ignore_yang_cmd,
	   "no bgp bestpath as-path ignore",
	   NO_STR BGP_STR
	   "Change the default bestpath selection\n"
	   "AS-path attribute\n"
	   "Ignore as-path length in selecting a route\n")
{
	nb_cli_enqueue_change(vty, "./global/route-selection-options/ignore-as-path-length",
			      NB_OP_MODIFY, "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_bestpath_aigp_yang, bgp_bestpath_aigp_yang_cmd,
	   "[no] bgp bestpath aigp",
	   NO_STR BGP_STR
	   "Change the default bestpath selection\n"
	   "Evaluate the AIGP attribute during the best path selection process\n")
{
	nb_cli_enqueue_change(vty, "./global/route-selection-options/compare-aigp", NB_OP_MODIFY,
			      no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_bestpath_use_imported_attrs_yang,
	   bgp_bestpath_use_imported_attrs_yang_cmd,
	   "[no] bgp bestpath use-imported-attributes",
	   NO_STR BGP_STR
	   "Change the default bestpath selection\n"
	   "Use imported path's attributes for bestpath comparison\n")
{
	nb_cli_enqueue_change(vty, "./global/route-selection-options/use-imported-attributes",
			      NB_OP_MODIFY, no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_bestpath_prefer_mpls_over_srv6_yang,
	   bgp_bestpath_prefer_mpls_over_srv6_yang_cmd,
	   "[no] bgp bestpath prefer-mpls-over-srv6",
	   NO_STR BGP_STR
	   "Change the default bestpath selection\n"
	   "Prefer the MPLS path over the SRv6 path\n")
{
	nb_cli_enqueue_change(vty, "./global/route-selection-options/prefer-mpls-over-srv6",
			      NB_OP_MODIFY, no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(bgp_bestpath_aspath_confed_yang, bgp_bestpath_aspath_confed_yang_cmd,
	   "bgp bestpath as-path confed",
	   BGP_STR
	   "Change the default bestpath selection\n"
	   "AS-path attribute\n"
	   "Compare path lengths including confederation sets & sequences in selecting a route\n")
{
	nb_cli_enqueue_change(vty, "./global/route-selection-options/aspath-confed", NB_OP_MODIFY,
			      "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_bestpath_aspath_confed_yang,
	   no_bgp_bestpath_aspath_confed_yang_cmd,
	   "no bgp bestpath as-path confed",
	   NO_STR BGP_STR
	   "Change the default bestpath selection\n"
	   "AS-path attribute\n"
	   "Compare path lengths including confederation sets & sequences in selecting a route\n")
{
	nb_cli_enqueue_change(vty, "./global/route-selection-options/aspath-confed", NB_OP_MODIFY,
			      "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(bgp_bestpath_aspath_multipath_relax_yang,
	   bgp_bestpath_aspath_multipath_relax_yang_cmd,
	   "bgp bestpath as-path multipath-relax [<as-set|no-as-set>]",
	   BGP_STR
	   "Change the default bestpath selection\n"
	   "AS-path attribute\n"
	   "Allow load sharing across routes that have different AS paths (but same length)\n"
	   "Generate an AS_SET\n"
	   "Do not generate an AS_SET\n")
{
	int idx = 0;

	nb_cli_enqueue_change(vty, "./global/route-selection-options/allow-multiple-as",
			      NB_OP_MODIFY, "true");
	nb_cli_enqueue_change(vty, "./global/route-selection-options/multi-path-as-set",
			      NB_OP_MODIFY,
			      argv_find(argv, argc, "as-set", &idx) ? "true" : "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_bestpath_aspath_multipath_relax_yang,
	   no_bgp_bestpath_aspath_multipath_relax_yang_cmd,
	   "no bgp bestpath as-path multipath-relax [<as-set|no-as-set>]",
	   NO_STR BGP_STR
	   "Change the default bestpath selection\n"
	   "AS-path attribute\n"
	   "Allow load sharing across routes that have different AS paths (but same length)\n"
	   "Generate an AS_SET\n"
	   "Do not generate an AS_SET\n")
{
	nb_cli_enqueue_change(vty, "./global/route-selection-options/multi-path-as-set",
			      NB_OP_DESTROY, NULL);
	nb_cli_enqueue_change(vty, "./global/route-selection-options/allow-multiple-as",
			      NB_OP_MODIFY, "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(bgp_bestpath_peer_type_multipath_relax_yang,
	   bgp_bestpath_peer_type_multipath_relax_yang_cmd,
	   "bgp bestpath peer-type multipath-relax",
	   BGP_STR
	   "Change the default bestpath selection\n"
	   "Peer type\n"
	   "Allow load sharing across routes learned from different peer types\n")
{
	nb_cli_enqueue_change(vty, "./global/route-selection-options/peer-type-multipath-relax",
			      NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_bestpath_peer_type_multipath_relax_yang,
	   no_bgp_bestpath_peer_type_multipath_relax_yang_cmd,
	   "no bgp bestpath peer-type multipath-relax",
	   NO_STR BGP_STR
	   "Change the default bestpath selection\n"
	   "Peer type\n"
	   "Allow load sharing across routes learned from different peer types\n")
{
	nb_cli_enqueue_change(vty, "./global/route-selection-options/peer-type-multipath-relax",
			      NB_OP_MODIFY, "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(bgp_bestpath_med_yang, bgp_bestpath_med_yang_cmd,
	   "bgp bestpath med <confed [missing-as-worst]|missing-as-worst [confed]>",
	   BGP_STR
	   "Change the default bestpath selection\n"
	   "MED attribute\n"
	   "Compare MED among confederation paths\n"
	   "Treat missing MED as the least preferred one\n"
	   "Treat missing MED as the least preferred one\n"
	   "Compare MED among confederation paths\n")
{
	int idx = 0;

	if (argv_find(argv, argc, "confed", &idx))
		nb_cli_enqueue_change(vty, "./global/route-selection-options/confed-med",
				      NB_OP_MODIFY, "true");
	idx = 0;
	if (argv_find(argv, argc, "missing-as-worst", &idx))
		nb_cli_enqueue_change(vty, "./global/route-selection-options/missing-as-worst-med",
				      NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_bestpath_med_yang, no_bgp_bestpath_med_yang_cmd,
	   "no bgp bestpath med <confed [missing-as-worst]|missing-as-worst [confed]>",
	   NO_STR BGP_STR
	   "Change the default bestpath selection\n"
	   "MED attribute\n"
	   "Compare MED among confederation paths\n"
	   "Treat missing MED as the least preferred one\n"
	   "Treat missing MED as the least preferred one\n"
	   "Compare MED among confederation paths\n")
{
	int idx = 0;

	if (argv_find(argv, argc, "confed", &idx))
		nb_cli_enqueue_change(vty, "./global/route-selection-options/confed-med",
				      NB_OP_MODIFY, "false");
	idx = 0;
	if (argv_find(argv, argc, "missing-as-worst", &idx))
		nb_cli_enqueue_change(vty, "./global/route-selection-options/missing-as-worst-med",
				      NB_OP_MODIFY, "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_bestpath_bw_yang, bgp_bestpath_bw_yang_cmd,
	   "bgp bestpath bandwidth <ignore|skip-missing|default-weight-for-missing>$bw_cfg",
	   BGP_STR
	   "Change the default bestpath selection\n"
	   "Link Bandwidth attribute\n"
	   "Ignore link bandwidth (i.e., do regular ECMP, not weighted)\n"
	   "Ignore paths without link bandwidth for ECMP (if other paths have it)\n"
	   "Assign a low default weight (value 1) to paths not having link bandwidth\n")
{
	nb_cli_enqueue_change(vty, "./global/route-selection-options/bandwidth-handling",
			      NB_OP_MODIFY, bw_cfg);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_bgp_bestpath_bw_yang, no_bgp_bestpath_bw_yang_cmd,
	   "no bgp bestpath bandwidth [<ignore|skip-missing|default-weight-for-missing>$bw_cfg]",
	   NO_STR BGP_STR
	   "Change the default bestpath selection\n"
	   "Link Bandwidth attribute\n"
	   "Ignore link bandwidth (i.e., do regular ECMP, not weighted)\n"
	   "Ignore paths without link bandwidth for ECMP (if other paths have it)\n"
	   "Assign a low default weight (value 1) to paths not having link bandwidth\n")
{
	nb_cli_enqueue_change(vty, "./global/route-selection-options/bandwidth-handling",
			      NB_OP_MODIFY, "ecmp");
	return nb_cli_apply_changes(vty, NULL);
}


static bool bgp_cli_holdtime_valid(unsigned long holdtime)
{
	return holdtime == 0 || holdtime >= 3;
}

DEFUN_YANG(bgp_timers_yang, bgp_timers_yang_cmd,
	   "timers bgp (0-65535) (0-65535)",
	   "Adjust routing timers\n"
	   "BGP timers\n"
	   "Keepalive interval\n"
	   "Holdtime\n")
{
	/* RFC 4271 4.2: hold time is either zero or at least three seconds. */
	if (!bgp_cli_holdtime_valid(strtoul(argv[3]->arg, NULL, 10))) {
		vty_out(vty, "%% hold time value must be either 0 or at least 3\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	nb_cli_enqueue_change(vty, "./global/global-config-timers/keepalive", NB_OP_MODIFY,
			      argv[2]->arg);
	nb_cli_enqueue_change(vty, "./global/global-config-timers/hold-time", NB_OP_MODIFY,
			      argv[3]->arg);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_timers_yang, no_bgp_timers_yang_cmd,
	   "no timers bgp [(0-65535) (0-65535)]",
	   NO_STR
	   "Adjust routing timers\n"
	   "BGP timers\n"
	   "Keepalive interval\n"
	   "Holdtime\n")
{
	char keepalive[16];
	char holdtime[16];

	snprintfrr(keepalive, sizeof(keepalive), "%lu", DFLT_BGP_KEEPALIVE);
	snprintfrr(holdtime, sizeof(holdtime), "%lu", DFLT_BGP_HOLDTIME);
	nb_cli_enqueue_change(vty, "./global/global-config-timers/keepalive", NB_OP_MODIFY,
			      keepalive);
	nb_cli_enqueue_change(vty, "./global/global-config-timers/hold-time", NB_OP_MODIFY,
			      holdtime);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(bgp_minimum_holdtime_yang, bgp_minimum_holdtime_yang_cmd,
	   "bgp minimum-holdtime (1-65535)",
	   "BGP specific commands\n"
	   "BGP minimum holdtime\n"
	   "Seconds\n")
{
	nb_cli_enqueue_change(vty, "./global/global-config-timers/minimum-holdtime", NB_OP_MODIFY,
			      argv[2]->arg);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_minimum_holdtime_yang, no_bgp_minimum_holdtime_yang_cmd,
	   "no bgp minimum-holdtime [(1-65535)]",
	   NO_STR
	   "BGP specific commands\n"
	   "BGP minimum holdtime\n"
	   "Seconds\n")
{
	nb_cli_enqueue_change(vty, "./global/global-config-timers/minimum-holdtime", NB_OP_DESTROY,
			      NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(bgp_confederation_identifier_yang,
	   bgp_confederation_identifier_yang_cmd,
	   "bgp confederation identifier ASNUM",
	   BGP_STR
	   "AS confederation parameters\n"
	   "Set routing domain confederation AS\n"
	   AS_STR)
{
	as_t as;
	char asplain[32];

	if (!asn_str2asn(argv[3]->arg, &as)) {
		vty_out(vty, "%% Invalid AS number: %s\n", argv[3]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}
	snprintfrr(asplain, sizeof(asplain), "%u", as);
	nb_cli_enqueue_change(vty, "./global/confederation/identifier", NB_OP_MODIFY, asplain);
	nb_cli_enqueue_change(vty, "./global/confederation/identifier-pretty", NB_OP_MODIFY,
			      argv[3]->arg);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_confederation_identifier_yang,
	   no_bgp_confederation_identifier_yang_cmd,
	   "no bgp confederation identifier [ASNUM]",
	   NO_STR BGP_STR
	   "AS confederation parameters\n"
	   "Set routing domain confederation AS\n"
	   AS_STR)
{
	nb_cli_enqueue_change(vty, "./global/confederation/identifier", NB_OP_DESTROY, NULL);
	nb_cli_enqueue_change(vty, "./global/confederation/identifier-pretty", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(bgp_confederation_peers_yang, bgp_confederation_peers_yang_cmd,
	   "bgp confederation peers ASNUM...",
	   BGP_STR
	   "AS confederation parameters\n"
	   "Peer ASs in BGP confederation\n"
	   AS_STR)
{
	int i;
	char xpath[XPATH_MAXLEN];
	as_t as;

	for (i = 3; i < argc; i++) {
		if (!asn_str2asn(argv[i]->arg, &as)) {
			vty_out(vty, "%% Invalid confed peer AS value: %s\n", argv[i]->arg);
			continue;
		}
		snprintfrr(xpath, sizeof(xpath), "./global/confederation/member-as[.='%s']",
			   asn_asn2asplain(as));
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
		snprintfrr(xpath, sizeof(xpath),
			   "./global/confederation/member-as-pretty[as='%s']/as-pretty",
			   asn_asn2asplain(as));
		nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, argv[i]->arg);
	}
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_confederation_peers_yang, no_bgp_confederation_peers_yang_cmd,
	   "no bgp confederation peers ASNUM...",
	   NO_STR BGP_STR
	   "AS confederation parameters\n"
	   "Peer ASs in BGP confederation\n"
	   AS_STR)
{
	int i;
	char xpath[XPATH_MAXLEN];
	as_t as;

	for (i = 4; i < argc; i++) {
		if (!asn_str2asn(argv[i]->arg, &as)) {
			vty_out(vty, "%% Invalid confed peer AS value: %s\n", argv[i]->arg);
			continue;
		}
		snprintfrr(xpath, sizeof(xpath), "./global/confederation/member-as[.='%s']",
			   asn_asn2asplain(as));
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
		snprintfrr(xpath, sizeof(xpath), "./global/confederation/member-as-pretty[as='%s']",
			   asn_asn2asplain(as));
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	}
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(bgp_maxmed_admin_yang, bgp_maxmed_admin_yang_cmd,
	   "bgp max-med administrative",
	   BGP_STR
	   "Advertise routes with max-med\n"
	   "Administratively applied, for an indefinite period\n")
{
	char value[16];
	int64_t maxmed = BGP_MAXMED_VALUE_DEFAULT;

	snprintfrr(value, sizeof(value), "%" PRId64, maxmed);
	nb_cli_enqueue_change(vty, "./global/med-config/enable-med-admin", NB_OP_MODIFY, "true");
	nb_cli_enqueue_change(vty, "./global/med-config/max-med-admin", NB_OP_MODIFY, value);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(bgp_maxmed_admin_medv_yang, bgp_maxmed_admin_medv_yang_cmd,
	   "bgp max-med administrative (0-4294967295)",
	   BGP_STR
	   "Advertise routes with max-med\n"
	   "Administratively applied, for an indefinite period\n"
	   "Max MED value to be used\n")
{
	nb_cli_enqueue_change(vty, "./global/med-config/enable-med-admin", NB_OP_MODIFY, "true");
	nb_cli_enqueue_change(vty, "./global/med-config/max-med-admin", NB_OP_MODIFY, argv[3]->arg);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_maxmed_admin_yang, no_bgp_maxmed_admin_yang_cmd,
	   "no bgp max-med administrative [(0-4294967295)]",
	   NO_STR BGP_STR
	   "Advertise routes with max-med\n"
	   "Administratively applied, for an indefinite period\n"
	   "Max MED value to be used\n")
{
	char value[16];
	int64_t maxmed = BGP_MAXMED_VALUE_DEFAULT;

	snprintfrr(value, sizeof(value), "%" PRId64, maxmed);
	nb_cli_enqueue_change(vty, "./global/med-config/enable-med-admin", NB_OP_MODIFY, "false");
	nb_cli_enqueue_change(vty, "./global/med-config/max-med-admin", NB_OP_MODIFY, value);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(bgp_maxmed_onstartup_yang, bgp_maxmed_onstartup_yang_cmd,
	   "bgp max-med on-startup (5-86400) [(0-4294967295)]",
	   BGP_STR
	   "Advertise routes with max-med\n"
	   "Effective on a startup\n"
	   "Time (seconds) period for max-med\n"
	   "Max MED value to be used\n")
{
	int idx = 0;
	char value[16];
	int64_t maxmed = BGP_MAXMED_VALUE_DEFAULT;

	argv_find(argv, argc, "(5-86400)", &idx);
	nb_cli_enqueue_change(vty, "./global/med-config/max-med-onstart-up-time", NB_OP_MODIFY,
			      argv[idx]->arg);
	idx = 0;
	if (argv_find(argv, argc, "(0-4294967295)", &idx))
		nb_cli_enqueue_change(vty, "./global/med-config/max-med-onstart-up-value",
				      NB_OP_MODIFY, argv[idx]->arg);
	else {
		snprintfrr(value, sizeof(value), "%" PRId64, maxmed);
		nb_cli_enqueue_change(vty, "./global/med-config/max-med-onstart-up-value",
				      NB_OP_MODIFY, value);
	}
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_maxmed_onstartup_yang, no_bgp_maxmed_onstartup_yang_cmd,
	   "no bgp max-med on-startup [(5-86400) [(0-4294967295)]]",
	   NO_STR BGP_STR
	   "Advertise routes with max-med\n"
	   "Effective on a startup\n"
	   "Time (seconds) period for max-med\n"
	   "Max MED value to be used\n")
{
	nb_cli_enqueue_change(vty, "./global/med-config/max-med-onstart-up-time", NB_OP_DESTROY,
			      NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_update_delay_yang, bgp_update_delay_yang_cmd,
	   "update-delay (0-3600)$delay [(1-3600)$wait]",
	   "Force initial delay for best-path and updates\n"
	   "Max delay in seconds\n"
	   "Establish wait in seconds\n")
{
	char wstr[16];

	nb_cli_enqueue_change(vty, "./global/global-config-timers/update-delay-time", NB_OP_MODIFY,
			      delay_str);
	snprintfrr(wstr, sizeof(wstr), "%" PRId64, wait ? wait : delay);
	nb_cli_enqueue_change(vty, "./global/global-config-timers/establish-wait-time",
			      NB_OP_MODIFY, wstr);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_update_delay_yang, no_bgp_update_delay_yang_cmd,
	   "no update-delay [(0-3600) [(1-3600)]]",
	   NO_STR
	   "Force initial delay for best-path and updates\n"
	   "Max delay in seconds\n"
	   "Establish wait in seconds\n")
{
	nb_cli_enqueue_change(vty, "./global/global-config-timers/update-delay-time",
			      NB_OP_DESTROY, NULL);
	nb_cli_enqueue_change(vty, "./global/global-config-timers/establish-wait-time",
			      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_advertisement_delay_yang, bgp_advertisement_delay_yang_cmd,
	   "advertisement-delay (1-3600)$delay",
	   "Hold route advertisements to peers for configured seconds after first peer establishes\n"
	   "Delay in seconds\n")
{
	nb_cli_enqueue_change(vty, "./global/global-config-timers/advertisement-delay-time",
			      NB_OP_MODIFY, delay_str);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_advertisement_delay_yang, no_bgp_advertisement_delay_yang_cmd,
	   "no advertisement-delay [(1-3600)]",
	   NO_STR
	   "Hold route advertisements to peers for configured seconds after first peer establishes\n"
	   "Delay in seconds\n")
{
	nb_cli_enqueue_change(vty, "./global/global-config-timers/advertisement-delay-time",
			      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}


DEFUN_YANG(bgp_listen_limit_yang, bgp_listen_limit_yang_cmd,
	   "bgp listen limit (1-65535)",
	   BGP_STR
	   "BGP Dynamic Neighbors listen commands\n"
	   "Maximum number of BGP Dynamic Neighbors that can be created\n"
	   "Configure Dynamic Neighbors listen limit value\n")
{
	nb_cli_enqueue_change(vty, "./global/global-neighbor-config/dynamic-neighbors-limit",
			      NB_OP_MODIFY, argv[3]->arg);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_listen_limit_yang, no_bgp_listen_limit_yang_cmd,
	   "no bgp listen limit [(1-65535)]",
	   NO_STR BGP_STR
	   "BGP Dynamic Neighbors listen commands\n"
	   "Maximum number of BGP Dynamic Neighbors that can be created\n"
	   "Configure Dynamic Neighbors listen limit value\n")
{
	nb_cli_enqueue_change(vty, "./global/global-neighbor-config/dynamic-neighbors-limit",
			      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_default_afi_safi_yang, bgp_default_afi_safi_yang_cmd,
	   "[no] bgp default <ipv4-unicast|ipv4-multicast|ipv4-vpn|ipv4-labeled-unicast|ipv4-flowspec|ipv6-unicast|ipv6-multicast|ipv6-vpn|ipv6-labeled-unicast|ipv6-flowspec|l2vpn-evpn>$afi_safi",
	   NO_STR BGP_STR
	   "Configure BGP defaults\n"
	   "Activate ipv4-unicast for a peer by default\n"
	   "Activate ipv4-multicast for a peer by default\n"
	   "Activate ipv4-vpn for a peer by default\n"
	   "Activate ipv4-labeled-unicast for a peer by default\n"
	   "Activate ipv4-flowspec for a peer by default\n"
	   "Activate ipv6-unicast for a peer by default\n"
	   "Activate ipv6-multicast for a peer by default\n"
	   "Activate ipv6-vpn for a peer by default\n"
	   "Activate ipv6-labeled-unicast for a peer by default\n"
	   "Activate ipv6-flowspec for a peer by default\n"
	   "Activate l2vpn-evpn for a peer by default\n")
{
	char xpath[XPATH_MAXLEN];

	snprintfrr(xpath, sizeof(xpath), "./global/default-afi-safi[.='%s']", afi_safi);
	nb_cli_enqueue_change(vty, xpath, no ? NB_OP_DESTROY : NB_OP_CREATE, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(bgp_graceful_restart_stalepath_time_yang,
	   bgp_graceful_restart_stalepath_time_yang_cmd,
	   "bgp graceful-restart stalepath-time (1-4095)",
	   BGP_STR
	   "Graceful restart capability parameters\n"
	   "Set the max time to hold onto restarting peer's stale paths\n"
	   "Delay value (seconds)\n")
{
	nb_cli_enqueue_change(vty, "./global/graceful-restart/stale-routes-time", NB_OP_MODIFY,
			      argv[3]->arg);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_graceful_restart_stalepath_time_yang,
	   no_bgp_graceful_restart_stalepath_time_yang_cmd,
	   "no bgp graceful-restart stalepath-time [(1-4095)]",
	   NO_STR BGP_STR
	   "Graceful restart capability parameters\n"
	   "Set the max time to hold onto restarting peer's stale paths\n"
	   "Delay value (seconds)\n")
{
	char val[16];

	snprintfrr(val, sizeof(val), "%u", BGP_DEFAULT_STALEPATH_TIME);
	nb_cli_enqueue_change(vty, "./global/graceful-restart/stale-routes-time", NB_OP_MODIFY,
			      val);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(bgp_graceful_restart_restart_time_yang,
	   bgp_graceful_restart_restart_time_yang_cmd,
	   "bgp graceful-restart restart-time (0-4095)",
	   BGP_STR
	   "Graceful restart capability parameters\n"
	   "Set the time to wait to delete stale routes before a BGP open message is received\n"
	   "Delay value (seconds)\n")
{
	nb_cli_enqueue_change(vty, "./global/graceful-restart/restart-time", NB_OP_MODIFY,
			      argv[3]->arg);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_graceful_restart_restart_time_yang,
	   no_bgp_graceful_restart_restart_time_yang_cmd,
	   "no bgp graceful-restart restart-time [(0-4095)]",
	   NO_STR BGP_STR
	   "Graceful restart capability parameters\n"
	   "Set the time to wait to delete stale routes before a BGP open message is received\n"
	   "Delay value (seconds)\n")
{
	char val[16];

	snprintfrr(val, sizeof(val), "%u", BGP_DEFAULT_RESTART_TIME);
	nb_cli_enqueue_change(vty, "./global/graceful-restart/restart-time", NB_OP_MODIFY, val);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(bgp_graceful_restart_select_defer_time_yang,
	   bgp_graceful_restart_select_defer_time_yang_cmd,
	   "bgp graceful-restart select-defer-time (0-3600)",
	   BGP_STR
	   "Graceful restart capability parameters\n"
	   "Set the time to defer the BGP route selection after restart\n"
	   "Delay value (seconds, 0 - disable)\n")
{
	nb_cli_enqueue_change(vty, "./global/graceful-restart/selection-deferral-time",
			      NB_OP_MODIFY, argv[3]->arg);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_graceful_restart_select_defer_time_yang,
	   no_bgp_graceful_restart_select_defer_time_yang_cmd,
	   "no bgp graceful-restart select-defer-time [(0-3600)]",
	   NO_STR BGP_STR
	   "Graceful restart capability parameters\n"
	   "Set the time to defer the BGP route selection after restart\n"
	   "Delay value (seconds, 0 - disable)\n")
{
	char val[16];

	snprintfrr(val, sizeof(val), "%u", BGP_DEFAULT_SELECT_DEFERRAL_TIME);
	nb_cli_enqueue_change(vty, "./global/graceful-restart/selection-deferral-time",
			      NB_OP_MODIFY, val);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(bgp_graceful_restart_rib_stale_time_yang,
	   bgp_graceful_restart_rib_stale_time_yang_cmd,
	   "bgp graceful-restart rib-stale-time (1-3600)",
	   BGP_STR
	   "Graceful restart configuration parameters\n"
	   "Specify the stale route removal timer in rib\n"
	   "Delay value (seconds)\n")
{
	nb_cli_enqueue_change(vty, "./global/graceful-restart/rib-stale-time", NB_OP_MODIFY,
			      argv[3]->arg);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_graceful_restart_rib_stale_time_yang,
	   no_bgp_graceful_restart_rib_stale_time_yang_cmd,
	   "no bgp graceful-restart rib-stale-time [(1-3600)]",
	   NO_STR BGP_STR
	   "Graceful restart configuration parameters\n"
	   "Specify the stale route removal timer in rib\n"
	   "Delay value (seconds)\n")
{
	char val[16];

	snprintfrr(val, sizeof(val), "%u", BGP_DEFAULT_RIB_STALE_TIME);
	nb_cli_enqueue_change(vty, "./global/graceful-restart/rib-stale-time", NB_OP_MODIFY, val);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(bgp_graceful_restart_preserve_fw_yang,
	   bgp_graceful_restart_preserve_fw_yang_cmd,
	   "bgp graceful-restart preserve-fw-state",
	   BGP_STR
	   "Graceful restart capability parameters\n"
	   "Sets F-bit indication that fib is preserved while doing Graceful Restart\n")
{
	nb_cli_enqueue_change(vty, "./global/graceful-restart/preserve-fw-entry", NB_OP_MODIFY,
			      "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_graceful_restart_preserve_fw_yang,
	   no_bgp_graceful_restart_preserve_fw_yang_cmd,
	   "no bgp graceful-restart preserve-fw-state",
	   NO_STR BGP_STR
	   "Graceful restart capability parameters\n"
	   "Sets F-bit indication that fib is preserved while doing Graceful Restart\n")
{
	nb_cli_enqueue_change(vty, "./global/graceful-restart/preserve-fw-entry", NB_OP_MODIFY,
			      "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_graceful_restart_notification_yang,
	   bgp_graceful_restart_notification_yang_cmd,
	   "[no] bgp graceful-restart notification",
	   NO_STR BGP_STR
	   "Graceful restart capability parameters\n"
	   "Indicate Graceful Restart support for BGP NOTIFICATION messages\n")
{
	nb_cli_enqueue_change(vty, "./global/graceful-restart/notification", NB_OP_MODIFY,
			      no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(bgp_graceful_restart_disable_eor_yang,
	   bgp_graceful_restart_disable_eor_yang_cmd,
	   "bgp graceful-restart disable-eor",
	   BGP_STR
	   "Graceful restart configuration parameters\n"
	   "Disable EOR Check\n")
{
	nb_cli_enqueue_change(vty, "./global/graceful-restart/disable-eor", NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_graceful_restart_disable_eor_yang,
	   no_bgp_graceful_restart_disable_eor_yang_cmd,
	   "no bgp graceful-restart disable-eor",
	   NO_STR BGP_STR
	   "Graceful restart configuration parameters\n"
	   "Disable EOR Check\n")
{
	nb_cli_enqueue_change(vty, "./global/graceful-restart/disable-eor", NB_OP_MODIFY, "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(bgp_llgr_stalepath_time_yang, bgp_llgr_stalepath_time_yang_cmd,
	   "bgp long-lived-graceful-restart stale-time (1-16777215)",
	   BGP_STR
	   "Enable Long-lived Graceful Restart\n"
	   "Specifies maximum time to wait before purging long-lived stale routes\n"
	   "Stale time value (seconds)\n")
{
	nb_cli_enqueue_change(vty, "./global/graceful-restart/long-lived-stale-time", NB_OP_MODIFY,
			      argv[3]->arg);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_llgr_stalepath_time_yang, no_bgp_llgr_stalepath_time_yang_cmd,
	   "no bgp long-lived-graceful-restart stale-time [(1-16777215)]",
	   NO_STR BGP_STR
	   "Enable Long-lived Graceful Restart\n"
	   "Specifies maximum time to wait before purging long-lived stale routes\n"
	   "Stale time value (seconds)\n")
{
	char val[16];

	snprintfrr(val, sizeof(val), "%u", BGP_DEFAULT_LLGR_STALE_TIME);
	nb_cli_enqueue_change(vty, "./global/graceful-restart/long-lived-stale-time", NB_OP_MODIFY,
			      val);
	return nb_cli_apply_changes(vty, NULL);
}


DEFUN_YANG(bgp_graceful_restart_yang, bgp_graceful_restart_yang_cmd,
	   "bgp graceful-restart", BGP_STR GR_CMD)
{
	nb_cli_enqueue_change(vty, "./global/graceful-restart/graceful-restart-disable",
			      NB_OP_DESTROY, NULL);
	nb_cli_enqueue_change(vty, "./global/graceful-restart/enabled", NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_graceful_restart_yang, no_bgp_graceful_restart_yang_cmd,
	   "no bgp graceful-restart", NO_STR BGP_STR NO_GR_CMD)
{
	nb_cli_enqueue_change(vty, "./global/graceful-restart/enabled", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(bgp_graceful_restart_disable_yang,
	   bgp_graceful_restart_disable_yang_cmd,
	   "bgp graceful-restart-disable", BGP_STR GR_DISABLE)
{
	nb_cli_enqueue_change(vty, "./global/graceful-restart/enabled", NB_OP_DESTROY, NULL);
	nb_cli_enqueue_change(vty, "./global/graceful-restart/graceful-restart-disable",
			      NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_graceful_restart_disable_yang,
	   no_bgp_graceful_restart_disable_yang_cmd,
	   "no bgp graceful-restart-disable", NO_STR BGP_STR NO_GR_DISABLE)
{
	nb_cli_enqueue_change(vty, "./global/graceful-restart/graceful-restart-disable",
			      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_tcp_keepalive_yang, bgp_tcp_keepalive_yang_cmd,
	   "bgp tcp-keepalive (1-65535)$idle (1-65535)$intvl (1-30)$probes",
	   BGP_STR
	   "TCP keepalive parameters\n"
	   "TCP keepalive idle time (seconds)\n"
	   "TCP keepalive interval (seconds)\n"
	   "TCP keepalive maximum probes\n")
{
	char idle_s[16], intvl_s[16], probes_s[16];

	snprintfrr(idle_s, sizeof(idle_s), "%" PRId64, idle);
	snprintfrr(intvl_s, sizeof(intvl_s), "%" PRId64, intvl);
	snprintfrr(probes_s, sizeof(probes_s), "%" PRId64, probes);
	nb_cli_enqueue_change(vty, "./global/global-config-timers/tcp-keepalive/idle",
			      NB_OP_MODIFY, idle_s);
	nb_cli_enqueue_change(vty, "./global/global-config-timers/tcp-keepalive/interval",
			      NB_OP_MODIFY, intvl_s);
	nb_cli_enqueue_change(vty, "./global/global-config-timers/tcp-keepalive/probes",
			      NB_OP_MODIFY, probes_s);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_tcp_keepalive_yang, no_bgp_tcp_keepalive_yang_cmd,
	   "no bgp tcp-keepalive [(1-65535) (1-65535) (1-30)]",
	   NO_STR BGP_STR
	   "TCP keepalive parameters\n"
	   "TCP keepalive idle time (seconds)\n"
	   "TCP keepalive interval (seconds)\n"
	   "TCP keepalive maximum probes\n")
{
	nb_cli_enqueue_change(vty, "./global/global-config-timers/tcp-keepalive/idle",
			      NB_OP_DESTROY, NULL);
	nb_cli_enqueue_change(vty, "./global/global-config-timers/tcp-keepalive/interval",
			      NB_OP_DESTROY, NULL);
	nb_cli_enqueue_change(vty, "./global/global-config-timers/tcp-keepalive/probes",
			      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_wpkt_quanta_yang, bgp_wpkt_quanta_yang_cmd,
	   "[no] write-quanta (1-64)$quanta",
	   NO_STR
	   "How many packets to write to peer socket per run\n"
	   "Number of packets\n")
{
	char val[16];
	int64_t value = no ? BGP_WRITE_PACKET_MAX : quanta;

	snprintfrr(val, sizeof(val), "%" PRId64, value);
	nb_cli_enqueue_change(vty,
			      "./global/global-neighbor-config/packet-quanta-config/wpkt-quanta",
			      NB_OP_MODIFY, val);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_rpkt_quanta_yang, bgp_rpkt_quanta_yang_cmd,
	   "[no] read-quanta (1-10)$quanta",
	   NO_STR
	   "How many packets to read from peer socket per I/O cycle\n"
	   "Number of packets\n")
{
	char val[16];
	int64_t value = no ? BGP_READ_PACKET_MAX : quanta;

	snprintfrr(val, sizeof(val), "%" PRId64, value);
	nb_cli_enqueue_change(vty,
			      "./global/global-neighbor-config/packet-quanta-config/rpkt-quanta",
			      NB_OP_MODIFY, val);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(bgp_coalesce_time_yang, bgp_coalesce_time_yang_cmd,
	   "coalesce-time (0-4294967295)",
	   "Subgroup coalesce timer\n"
	   "Subgroup coalesce timer value (in ms)\n")
{
	nb_cli_enqueue_change(vty, "./global/global-update-group-config/coalesce-time",
			      NB_OP_MODIFY, argv[1]->arg);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_coalesce_time_yang, no_bgp_coalesce_time_yang_cmd,
	   "no coalesce-time [(0-4294967295)]",
	   NO_STR
	   "Subgroup coalesce timer\n"
	   "Subgroup coalesce timer value (in ms)\n")
{
	char val[16];

	snprintfrr(val, sizeof(val), "%u", BGP_DEFAULT_SUBGROUP_COALESCE_TIME);
	nb_cli_enqueue_change(vty, "./global/global-update-group-config/coalesce-time",
			      NB_OP_MODIFY, val);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(bgp_default_subgroup_pkt_queue_max_yang,
	   bgp_default_subgroup_pkt_queue_max_yang_cmd,
	   "bgp default subgroup-pkt-queue-max (20-100)",
	   BGP_STR
	   "Configure BGP defaults\n"
	   "subgroup-pkt-queue-max\n"
	   "Configure subgroup packet queue max\n")
{
	nb_cli_enqueue_change(vty, "./global/global-update-group-config/subgroup-pkt-queue-size",
			      NB_OP_MODIFY, argv[3]->arg);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_default_subgroup_pkt_queue_max_yang,
	   no_bgp_default_subgroup_pkt_queue_max_yang_cmd,
	   "no bgp default subgroup-pkt-queue-max [(20-100)]",
	   NO_STR BGP_STR
	   "Configure BGP defaults\n"
	   "subgroup-pkt-queue-max\n"
	   "Configure subgroup packet queue max\n")
{
	char val[16];

	snprintfrr(val, sizeof(val), "%u", BGP_DEFAULT_SUBGROUP_PKT_QUEUE_MAX);
	nb_cli_enqueue_change(vty, "./global/global-update-group-config/subgroup-pkt-queue-size",
			      NB_OP_MODIFY, val);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_default_shutdown_yang, bgp_default_shutdown_yang_cmd,
	   "[no] bgp default shutdown",
	   NO_STR BGP_STR
	   "Configure BGP defaults\n"
	   "Apply administrative shutdown to newly configured peers\n")
{
	nb_cli_enqueue_change(vty, "./global/default-shutdown", NB_OP_MODIFY,
			      no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(bgp_shutdown_yang, bgp_shutdown_yang_cmd, "bgp shutdown",
	   BGP_STR "Administrative shutdown of the BGP instance\n")
{
	nb_cli_enqueue_change(vty, "./global/shutdown-message", NB_OP_DESTROY, NULL);
	nb_cli_enqueue_change(vty, "./global/shutdown-no-notify", NB_OP_DESTROY, NULL);
	nb_cli_enqueue_change(vty, "./global/shutdown", NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(bgp_shutdown_no_notify_yang, bgp_shutdown_no_notify_yang_cmd,
	   "bgp shutdown no-notify",
	   BGP_STR
	   "Administrative shutdown of the BGP instance\n"
	   "Do not send BGP notification (for HA standby transition)\n")
{
	nb_cli_enqueue_change(vty, "./global/shutdown-message", NB_OP_DESTROY, NULL);
	nb_cli_enqueue_change(vty, "./global/shutdown", NB_OP_MODIFY, "true");
	nb_cli_enqueue_change(vty, "./global/shutdown-no-notify", NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(bgp_shutdown_msg_yang, bgp_shutdown_msg_yang_cmd,
	   "bgp shutdown message MSG...",
	   BGP_STR
	   "Administrative shutdown of the BGP instance\n"
	   "Add a shutdown message (RFC 8203)\n"
	   "Shutdown message\n")
{
	char *msgstr;

	msgstr = argv_concat(argv, argc, 3);
	nb_cli_enqueue_change(vty, "./global/shutdown-no-notify", NB_OP_DESTROY, NULL);
	nb_cli_enqueue_change(vty, "./global/shutdown", NB_OP_MODIFY, "true");
	nb_cli_enqueue_change(vty, "./global/shutdown-message", NB_OP_MODIFY, msgstr);
	XFREE(MTYPE_TMP, msgstr);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_shutdown_yang, no_bgp_shutdown_yang_cmd, "no bgp shutdown",
	   NO_STR BGP_STR "Administrative shutdown of the BGP instance\n")
{
	nb_cli_enqueue_change(vty, "./global/shutdown-message", NB_OP_DESTROY, NULL);
	nb_cli_enqueue_change(vty, "./global/shutdown-no-notify", NB_OP_DESTROY, NULL);
	nb_cli_enqueue_change(vty, "./global/shutdown", NB_OP_MODIFY, "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_shutdown_msg_yang, no_bgp_shutdown_msg_yang_cmd,
	   "no bgp shutdown message MSG...",
	   NO_STR BGP_STR
	   "Administrative shutdown of the BGP instance\n"
	   "Add a shutdown message (RFC 8203)\n"
	   "Shutdown message\n")
{
	nb_cli_enqueue_change(vty, "./global/shutdown-message", NB_OP_DESTROY, NULL);
	nb_cli_enqueue_change(vty, "./global/shutdown-no-notify", NB_OP_DESTROY, NULL);
	nb_cli_enqueue_change(vty, "./global/shutdown", NB_OP_MODIFY, "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_shutdown_no_notify_yang, no_bgp_shutdown_no_notify_yang_cmd,
	   "no bgp shutdown no-notify",
	   NO_STR BGP_STR
	   "Administrative shutdown of the BGP instance\n"
	   "Do not send BGP notification (for HA standby transition)\n")
{
	nb_cli_enqueue_change(vty, "./global/shutdown-message", NB_OP_DESTROY, NULL);
	nb_cli_enqueue_change(vty, "./global/shutdown-no-notify", NB_OP_DESTROY, NULL);
	nb_cli_enqueue_change(vty, "./global/shutdown", NB_OP_MODIFY, "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_allow_martian_yang, bgp_allow_martian_yang_cmd,
	   "[no] bgp allow-martian-nexthop",
	   NO_STR BGP_STR
	   "Allow Martian nexthops to be received in the NLRI from a peer\n")
{
	nb_cli_enqueue_change(vty, "./global/allow-martian-nexthop", NB_OP_MODIFY,
			      no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_use_underlying_nexthop_weight_yang,
	   bgp_use_underlying_nexthop_weight_yang_cmd,
	   "[no] use-underlays-nexthop-weight",
	   NO_STR
	   "Tell Zebra when resolving a route to use the underlays nexthop weight for when nexthops are resolved\n")
{
	nb_cli_enqueue_change(vty, "./global/use-underlays-nexthop-weight", NB_OP_MODIFY,
			      no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_suppress_fib_pending_yang, bgp_suppress_fib_pending_yang_cmd,
	   "[no] bgp suppress-fib-pending [(0-10000)$delay]",
	   NO_STR BGP_STR
	   "Advertise only routes that are programmed in kernel to peers\n"
	   "Advertisement delay in milliseconds after FIB installation (default 1000)\n")
{
	char val[16];
	int64_t adv_delay = delay_str ? delay : BGP_DEFAULT_SUPPRESS_FIB_ADV_DELAY;

	if (no) {
		nb_cli_enqueue_change(vty, "./global/suppress-fib-pending-delay", NB_OP_DESTROY,
				      NULL);
		nb_cli_enqueue_change(vty, "./global/suppress-fib-pending", NB_OP_MODIFY, "false");
	} else {
		snprintfrr(val, sizeof(val), "%" PRId64, adv_delay);
		nb_cli_enqueue_change(vty, "./global/suppress-fib-pending", NB_OP_MODIFY, "true");
		nb_cli_enqueue_change(vty, "./global/suppress-fib-pending-delay", NB_OP_MODIFY,
				      val);
	}
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(bgp_fast_convergence_yang, bgp_fast_convergence_yang_cmd,
	   "bgp fast-convergence",
	   BGP_STR "Fast convergence for bgp sessions\n")
{
	nb_cli_enqueue_change(vty, "./global/fast-convergence", NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_fast_convergence_yang, no_bgp_fast_convergence_yang_cmd,
	   "no bgp fast-convergence",
	   NO_STR BGP_STR "Fast convergence for bgp sessions\n")
{
	nb_cli_enqueue_change(vty, "./global/fast-convergence", NB_OP_MODIFY, "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_ipv6_auto_ra_yang, bgp_ipv6_auto_ra_yang_cmd,
	   "[no] bgp ipv6-auto-ra",
	   NO_STR BGP_STR "Allow enabling IPv6 ND RA sending\n")
{
	nb_cli_enqueue_change(vty, "./global/ipv6-auto-ra", NB_OP_MODIFY, no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_lu_uses_explicit_null_yang, bgp_lu_uses_explicit_null_yang_cmd,
	   "[no] bgp labeled-unicast <explicit-null|ipv4-explicit-null|ipv6-explicit-null>$value",
	   NO_STR BGP_STR
	   "BGP Labeled-unicast options\n"
	   "Use explicit-null label values for all local prefixes\n"
	   "Use the IPv4 explicit-null label value for IPv4 local prefixes\n"
	   "Use the IPv6 explicit-null label value for IPv6 local prefixes\n")
{
	char check[XPATH_MAXLEN + 256];
	const struct lyd_node *cand = vty->candidate_config ? vty->candidate_config->dnode : NULL;
	bool v4 = false, v6 = false;
	const char *val;

	snprintfrr(check, sizeof(check), "%s/global/labeled-unicast-explicit-null", VTY_CURR_XPATH);
	if (cand && yang_dnode_exists(cand, check)) {
		const char *cur = yang_dnode_get_string(cand, "%s", check);

		if (strmatch(cur, "explicit-null")) {
			v4 = true;
			v6 = true;
		} else if (strmatch(cur, "ipv4-explicit-null")) {
			v4 = true;
		} else if (strmatch(cur, "ipv6-explicit-null")) {
			v6 = true;
		}
	}

	if (strmatch(value, "ipv4-explicit-null"))
		v4 = !no;
	else if (strmatch(value, "ipv6-explicit-null"))
		v6 = !no;
	else {
		v4 = !no;
		v6 = !no;
	}

	if (v4 && v6)
		val = "explicit-null";
	else if (v4)
		val = "ipv4-explicit-null";
	else if (v6)
		val = "ipv6-explicit-null";
	else
		val = "none";

	nb_cli_enqueue_change(vty, "./global/labeled-unicast-explicit-null", NB_OP_MODIFY, val);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_default_dynamic_capability_yang,
	   bgp_default_dynamic_capability_yang_cmd,
	   "[no] bgp default dynamic-capability",
	   NO_STR BGP_STR
	   "Configure BGP defaults\n"
	   "Advertise dynamic capability for all neighbors\n")
{
	nb_cli_enqueue_change(vty, "./global/default-dynamic-capability", NB_OP_MODIFY,
			      no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_default_link_local_capability_yang,
	   bgp_default_link_local_capability_yang_cmd,
	   "[no] bgp default link-local-capability",
	   NO_STR BGP_STR
	   "Configure BGP defaults\n"
	   "Advertise Link-Local Next Hop capability for all neighbors\n")
{
	nb_cli_enqueue_change(vty, "./global/default-link-local-capability", NB_OP_MODIFY,
			      no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_default_software_version_capability_yang,
	   bgp_default_software_version_capability_yang_cmd,
	   "[no] bgp default software-version-capability [latest-encoding$latest_encoding]",
	   NO_STR BGP_STR
	   "Configure BGP defaults\n"
	   "Advertise software version capability for all neighbors\n"
	   "Use the latest-encoding defined in draft-abraitis-bgp-version-capability-15\n")
{
	const char *val;

	if (no) {
		VTY_DECLVAR_CONTEXT(bgp, bgp);
		bool old = CHECK_FLAG(bgp->flags, BGP_FLAG_SOFT_VERSION_CAPABILITY_OLD);
		bool latest = CHECK_FLAG(bgp->flags, BGP_FLAG_SOFT_VERSION_CAPABILITY_NEW);

		if (latest_encoding)
			latest = false;
		else
			old = false;

		if (latest)
			val = "latest-encoding";
		else if (old)
			val = "old-encoding";
		else
			val = "disabled";
	} else if (latest_encoding) {
		val = "latest-encoding";
	} else {
		val = "old-encoding";
	}

	nb_cli_enqueue_change(vty, "./global/default-software-version-capability", NB_OP_MODIFY,
			      val);
	return nb_cli_apply_changes(vty, NULL);
}

/*
 * Neighbor / peer-group xpath helper.
 * Returns 0 on success. Canonicalizes IPv4/IPv6 addresses for YANG list keys,
 * rejects dynamic peers, and (unless allow_create is true) rejects missing IP
 * neighbors with classic peer_and_group_lookup_vty() errors. For WORD, prefers
 * an existing unnumbered neighbor in the candidate, otherwise peer-group.
 */
static int bgp_cli_neighbor_base_xpath_common(struct vty *vty, const char *neighbor, char *xpath,
					      size_t xpath_len, bool *is_peer_group,
					      bool allow_create)
{
	char check[XPATH_MAXLEN + 256];
	union sockunion su;

	*is_peer_group = false;

	if (str2sockunion(neighbor, &su) >= 0) {
		char canon[SU_ADDRSTRLEN];
		const struct lyd_node *bgp_dn;
		struct bgp *bgp;

		if (!sockunion2str(&su, canon, sizeof(canon))) {
			vty_out(vty, "%% Malformed address\n");
			return -1;
		}

		bgp_dn = yang_dnode_get(running_config->dnode, VTY_CURR_XPATH);
		bgp = bgp_dn ? nb_running_get_entry(bgp_dn, NULL, false) : NULL;
		if (bgp) {
			struct peer *peer = peer_lookup(bgp, &su);

			if (peer && peer_dynamic_neighbor(peer)) {
				vty_out(vty, "%% Operation not allowed on a dynamic neighbor\n");
				return -1;
			}
		}

		if (!allow_create) {
			snprintfrr(check, sizeof(check),
				   "%s/neighbors/neighbor[remote-address='%s']", VTY_CURR_XPATH,
				   canon);
			if (!yang_dnode_exists(vty->candidate_config->dnode, check)) {
				vty_out(vty, "%% Specify remote-as or peer-group commands first\n");
				return -1;
			}
		}

		snprintfrr(xpath, xpath_len, "./neighbors/neighbor[remote-address='%s']", canon);
		return 0;
	}

	snprintfrr(check, sizeof(check), "%s/neighbors/unnumbered-neighbor[interface='%s']",
		   VTY_CURR_XPATH, neighbor);
	if (yang_dnode_exists(vty->candidate_config->dnode, check)) {
		snprintfrr(xpath, xpath_len, "./neighbors/unnumbered-neighbor[interface='%s']",
			   neighbor);
		return 0;
	}

	snprintfrr(check, sizeof(check), "%s/peer-groups/peer-group[peer-group-name='%s']",
		   VTY_CURR_XPATH, neighbor);
	if (!yang_dnode_exists(vty->candidate_config->dnode, check)) {
		vty_out(vty, "%% Create the peer-group or interface first\n");
		return -1;
	}

	snprintfrr(xpath, xpath_len, "./peer-groups/peer-group[peer-group-name='%s']", neighbor);
	*is_peer_group = true;
	return 0;
}

static int bgp_cli_neighbor_base_xpath(struct vty *vty, const char *neighbor, char *xpath,
				       size_t xpath_len, bool *is_peer_group)
{
	return bgp_cli_neighbor_base_xpath_common(vty, neighbor, xpath, xpath_len, is_peer_group,
						  false);
}

static int bgp_cli_neighbor_create_xpath(struct vty *vty, const char *neighbor, char *xpath,
					 size_t xpath_len, bool *is_peer_group)
{
	return bgp_cli_neighbor_base_xpath_common(vty, neighbor, xpath, xpath_len, is_peer_group,
						  true);
}

static int bgp_cli_enqueue_remote_as(struct vty *vty, const char *base_xpath, const char *as_str,
				     bool internal, bool external, bool as_auto)
{
	char leaf[XPATH_MAXLEN + 256];
	const char *as_type;

	if (as_str) {
		as_t as_num;

		if (!asn_str2asn(as_str, &as_num)) {
			vty_out(vty, "%% Invalid AS number: %s\n", as_str);
			return CMD_WARNING_CONFIG_FAILED;
		}
		as_type = "as-specified";
		snprintfrr(leaf, sizeof(leaf), "%s/neighbor-remote-as/remote-as-type", base_xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, as_type);
		snprintfrr(leaf, sizeof(leaf), "%s/neighbor-remote-as/remote-as", base_xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, asn_asn2asplain(as_num));
	} else if (internal) {
		snprintfrr(leaf, sizeof(leaf), "%s/neighbor-remote-as/remote-as-type", base_xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, "internal");
	} else if (as_auto) {
		snprintfrr(leaf, sizeof(leaf), "%s/neighbor-remote-as/remote-as-type", base_xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, "auto");
	} else {
		snprintfrr(leaf, sizeof(leaf), "%s/neighbor-remote-as/remote-as-type", base_xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, "external");
	}
	return CMD_SUCCESS;
}

struct bgp_cli_pg_member {
	struct bgp_cli_pg_member *next;
	bool unnumbered;
	char *id;
};

static void bgp_cli_pg_members_free(struct bgp_cli_pg_member *member)
{
	struct bgp_cli_pg_member *next;

	while (member) {
		next = member->next;
		XFREE(MTYPE_TMP, member->id);
		XFREE(MTYPE_TMP, member);
		member = next;
	}
}

static void bgp_cli_pg_member_note(struct bgp_cli_pg_member **head, bool unnumbered, const char *id)
{
	struct bgp_cli_pg_member *member;

	member = XCALLOC(MTYPE_TMP, sizeof(*member));
	member->unnumbered = unnumbered;
	member->id = XSTRDUP(MTYPE_TMP, id);
	member->next = *head;
	*head = member;
}

/* Configured neighbors whose peer-group leaf names this group. */
static struct bgp_cli_pg_member *bgp_cli_peer_group_members(struct vty *vty, const char *pg)
{
	struct bgp_cli_pg_member *head = NULL;
	const struct lyd_node *nbrs, *nbr;
	char check[XPATH_MAXLEN + 64];

	snprintfrr(check, sizeof(check), "%s/neighbors", VTY_CURR_XPATH);
	nbrs = yang_dnode_get(vty->candidate_config->dnode, check);
	if (!nbrs)
		return NULL;

	for (nbr = lyd_child(nbrs); nbr; nbr = nbr->next) {
		bool unnumbered;
		const char *bound, *id;

		if (nbr->schema->nodetype != LYS_LIST)
			continue;
		if (strmatch(nbr->schema->name, "neighbor"))
			unnumbered = false;
		else if (strmatch(nbr->schema->name, "unnumbered-neighbor"))
			unnumbered = true;
		else
			continue;
		if (!yang_dnode_exists(nbr, "./peer-group"))
			continue;
		bound = yang_dnode_get_string(nbr, "./peer-group");
		if (!bound || !strmatch(bound, pg))
			continue;
		id = yang_dnode_get_string(nbr, unnumbered ? "./interface" : "./remote-address");
		if (id)
			bgp_cli_pg_member_note(&head, unnumbered, id);
	}
	return head;
}

static uint32_t bgp_cli_peer_group_listen_ranges(struct vty *vty, const char *pg)
{
	const struct lyd_node *group, *child;
	char check[XPATH_MAXLEN + 256];
	uint32_t count = 0;

	snprintfrr(check, sizeof(check), "%s/peer-groups/peer-group[peer-group-name='%s']",
		   VTY_CURR_XPATH, pg);
	group = yang_dnode_get(vty->candidate_config->dnode, check);
	if (!group)
		return 0;

	for (child = lyd_child(group); child; child = child->next) {
		if (child->schema->nodetype != LYS_LEAFLIST)
			continue;
		if (strmatch(child->schema->name, "ipv4-listen-range") ||
		    strmatch(child->schema->name, "ipv6-listen-range"))
			count++;
	}
	return count;
}

/*
 * Classic "no neighbor PG peer-group" deletes the group and every member.
 * Each member peer-group leaf is a leafref, so deleting only the group is
 * rejected before the runtime destroy callback runs.
 */
static int bgp_cli_enqueue_peer_group_delete(struct vty *vty, const char *pg)
{
	struct bgp_cli_pg_member *members, *member;
	char xpath[XPATH_MAXLEN];
	char check[XPATH_MAXLEN + 256];
	uint32_t nlisten;

	snprintfrr(check, sizeof(check), "%s/peer-groups/peer-group[peer-group-name='%s']",
		   VTY_CURR_XPATH, pg);
	if (!yang_dnode_exists(vty->candidate_config->dnode, check)) {
		vty_out(vty, "%% Create the peer-group first\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	nlisten = bgp_cli_peer_group_listen_ranges(vty, pg);
	if (nlisten) {
		vty_out(vty,
			"%%Peer-group %s is attached to %u listen-range(s), delete them first\n",
			pg, nlisten);
		return CMD_WARNING_CONFIG_FAILED;
	}

	members = bgp_cli_peer_group_members(vty, pg);
	for (member = members; member; member = member->next) {
		if (member->unnumbered)
			snprintfrr(xpath, sizeof(xpath),
				   "./neighbors/unnumbered-neighbor[interface='%s']", member->id);
		else
			snprintfrr(xpath, sizeof(xpath),
				   "./neighbors/neighbor[remote-address='%s']", member->id);
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	}
	bgp_cli_pg_members_free(members);

	snprintfrr(xpath, sizeof(xpath), "./peer-groups/peer-group[peer-group-name='%s']", pg);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return CMD_SUCCESS;
}

DEFPY_YANG(neighbor_peer_group_yang, neighbor_peer_group_yang_cmd,
	   "[no] neighbor WORD$pg peer-group",
	   NO_STR NEIGHBOR_STR
	   "Neighbor tag\n"
	   "Configure peer-group\n")
{
	if (no) {
		int ret;

		ret = bgp_cli_enqueue_peer_group_delete(vty, pg);
		if (ret != CMD_SUCCESS)
			return ret;
	} else {
		char xpath[XPATH_MAXLEN];

		snprintfrr(xpath, sizeof(xpath), "./peer-groups/peer-group[peer-group-name='%s']",
			   pg);
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	}

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_remote_as_yang, neighbor_remote_as_yang_cmd,
	   "neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor remote-as <ASNUM$as|internal$internal|external$external|auto$as_auto>",
	   NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Specify a BGP neighbor\n"
	   AS_STR
	   "Internal BGP peer\n"
	   "External BGP peer\n"
	   "Automatically detect remote ASN\n")
{
	char xpath[XPATH_MAXLEN];
	bool is_pg = false;
	int ret;

	ret = bgp_cli_neighbor_create_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	/* Numbered neighbors are created by remote-as; peer-groups must exist. */
	if (!is_pg)
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	ret = bgp_cli_enqueue_remote_as(vty, xpath, as_str, !!internal, !!external, !!as_auto);
	if (ret != CMD_SUCCESS)
		return ret;
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_neighbor_yang, no_neighbor_yang_cmd,
	   "no neighbor <WORD|<A.B.C.D|X:X::X:X> [remote-as <ASNUM|internal|external|auto>]>",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Specify a BGP neighbor\n"
	   AS_STR
	   "Internal BGP peer\n"
	   "External BGP peer\n"
	   "Automatically detect remote ASN\n")
{
	char xpath[XPATH_MAXLEN];
	bool is_pg = false;
	int ret;
	const char *peer_str = argv[2]->arg;

	ret = bgp_cli_neighbor_base_xpath(vty, peer_str, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	/*
	 * "no neighbor PG" is the other classic way to delete a peer-group,
	 * and it removed the members too. Same leafref constraint as
	 * "no neighbor PG peer-group".
	 */
	if (is_pg) {
		ret = bgp_cli_enqueue_peer_group_delete(vty, peer_str);
		if (ret != CMD_SUCCESS)
			return ret;
	} else
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_neighbor_remote_as_yang, no_neighbor_remote_as_yang_cmd,
	   "no neighbor WORD$neighbor remote-as <ASNUM|internal|external|auto>",
	   NO_STR NEIGHBOR_STR
	   "Interface name or neighbor tag\n"
	   "Specify a BGP neighbor\n"
	   AS_STR
	   "Internal BGP peer\n"
	   "External BGP peer\n"
	   "Automatically detect remote ASN\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret < 0)
		return CMD_WARNING_CONFIG_FAILED;
	if (ret > 0) {
		vty_out(vty, "%% Create the peer-group or interface first\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	snprintfrr(leaf, sizeof(leaf), "%s/neighbor-remote-as/remote-as", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/neighbor-remote-as/remote-as-type", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

/*
 * Positive forms are separate commands so peer-group and remote-as cannot
 * be combined. The no form ignores the optional words and deletes the neighbor.
 */
static int bgp_cli_neighbor_interface_create(struct vty *vty, const char *ifname,
					     const char *v6only, const char *peergroup,
					     const char *as_str, const char *internal,
					     const char *external, const char *as_auto)
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];

	snprintfrr(xpath, sizeof(xpath), "./neighbors/unnumbered-neighbor[interface='%s']", ifname);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	if (v6only) {
		snprintfrr(leaf, sizeof(leaf), "%s/v6only", xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, "true");
	}

	if (peergroup) {
		snprintfrr(leaf, sizeof(leaf), "%s/peer-group", xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, peergroup);
	}

	if (as_str || internal || external || as_auto) {
		int ret = bgp_cli_enqueue_remote_as(vty, xpath, as_str, !!internal, !!external,
						    !!as_auto);
		if (ret != CMD_SUCCESS)
			return ret;
	}

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_interface_config_yang, neighbor_interface_config_yang_cmd,
	   "neighbor WORD$ifname interface [v6only$v6only]",
	   NEIGHBOR_STR
	   "Interface name\n"
	   "Enable BGP on interface\n"
	   "Enable BGP with v6 link-local only\n")
{
	return bgp_cli_neighbor_interface_create(vty, ifname, v6only, NULL, NULL, NULL, NULL,
						 NULL);
}

DEFPY_YANG(neighbor_interface_peer_group_yang, neighbor_interface_peer_group_yang_cmd,
	   "neighbor WORD$ifname interface [v6only$v6only] peer-group WORD$peergroup",
	   NEIGHBOR_STR
	   "Interface name\n"
	   "Enable BGP on interface\n"
	   "Enable BGP with v6 link-local only\n"
	   "Member of the peer-group\n"
	   "Peer-group name\n")
{
	return bgp_cli_neighbor_interface_create(vty, ifname, v6only, peergroup, NULL, NULL, NULL,
						 NULL);
}

DEFPY_YANG(neighbor_interface_remote_as_yang, neighbor_interface_remote_as_yang_cmd,
	   "neighbor WORD$ifname interface [v6only$v6only] remote-as <ASNUM$as|internal$internal|external$external|auto$as_auto>",
	   NEIGHBOR_STR
	   "Interface name\n"
	   "Enable BGP on interface\n"
	   "Enable BGP with v6 link-local only\n"
	   "Specify a BGP neighbor\n"
	   AS_STR
	   "Internal BGP peer\n"
	   "External BGP peer\n"
	   "Automatically detect remote ASN\n")
{
	return bgp_cli_neighbor_interface_create(vty, ifname, v6only, NULL, as_str, internal,
						 external, as_auto);
}

DEFPY_YANG(no_neighbor_interface_config_yang, no_neighbor_interface_config_yang_cmd,
	   "no neighbor WORD$ifname interface [v6only] [peer-group WORD] [remote-as <ASNUM|internal|external|auto>]",
	   NO_STR NEIGHBOR_STR
	   "Interface name\n"
	   "Enable BGP on interface\n"
	   "Enable BGP with v6 link-local only\n"
	   "Member of the peer-group\n"
	   "Peer-group name\n"
	   "Specify a BGP neighbor\n"
	   AS_STR
	   "Internal BGP peer\n"
	   "External BGP peer\n"
	   "Automatically detect remote ASN\n")
{
	char xpath[XPATH_MAXLEN];
	char check[XPATH_MAXLEN + 256];

	snprintfrr(check, sizeof(check), "%s/neighbors/unnumbered-neighbor[interface='%s']",
		   VTY_CURR_XPATH, ifname);
	if (!yang_dnode_exists(vty->candidate_config->dnode, check)) {
		vty_out(vty, "%% Create the bgp interface first\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	snprintfrr(xpath, sizeof(xpath), "./neighbors/unnumbered-neighbor[interface='%s']", ifname);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_password_yang, neighbor_password_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor password [LINE$password]",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Set a password\n"
	   "The password\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	int ret;

	if (!no && !password) {
		vty_out(vty, "%% Password required\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	snprintfrr(leaf, sizeof(leaf), "%s/password", xpath);
	if (no)
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, password);

	ret = nb_cli_apply_changes(vty, NULL);

	/*
	 * Removing the password from a peer-group may leave an open listen
	 * range (0.0.0.0/0 or ::/0) unprotected (db1ca25485). Skip it while
	 * frr.conf is loading.
	 */
	if (ret == CMD_SUCCESS && no && is_pg && !bgp_config_inprocess()) {
		struct bgp *bgp = VTY_GET_CONTEXT(bgp);
		struct peer_group *group = bgp ? peer_group_lookup(bgp, neighbor) : NULL;

		if (group && !group->conf->password)
			bgp_listen_range_warn_group(vty, group);
	}

	return ret;
}

DEFPY_YANG(neighbor_description_yang, neighbor_description_yang_cmd,
	   "neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor description LINE...",
	   NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Neighbor specific description\n"
	   "Up to 80 characters describing this neighbor\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	char *str;
	bool is_pg = false;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	str = argv_concat(argv, argc, 3);
	snprintfrr(leaf, sizeof(leaf), "%s/description", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, str);
	XFREE(MTYPE_TMP, str);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_neighbor_description_yang, no_neighbor_description_yang_cmd,
	   "no neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor description",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Neighbor specific description\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	snprintfrr(leaf, sizeof(leaf), "%s/description", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

/* Classic keeps the running-config text as a valid no-form via an alias. */
DEFPY_YANG(no_neighbor_description_comment_yang, no_neighbor_description_comment_yang_cmd,
	   "no neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor description LINE...",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Neighbor specific description\n"
	   "Up to 80 characters describing this neighbor\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	snprintfrr(leaf, sizeof(leaf), "%s/description", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_passive_yang, neighbor_passive_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor passive",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Don't send open messages to this neighbor\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	snprintfrr(leaf, sizeof(leaf), "%s/passive-mode", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_solo_yang, neighbor_solo_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor solo",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Solo peer - part of its own update group\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	snprintfrr(leaf, sizeof(leaf), "%s/solo", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_shutdown_yang, neighbor_shutdown_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor shutdown",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Administratively shut down this neighbor\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	snprintfrr(leaf, sizeof(leaf), "%s/admin-shutdown/message", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/admin-shutdown/enable", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_shutdown_msg_yang, neighbor_shutdown_msg_yang_cmd,
	   "neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor shutdown message MSG...",
	   NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Administratively shut down this neighbor\n"
	   "Add a shutdown message (RFC 8203)\n"
	   "Shutdown message\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	char *msgstr;
	bool is_pg = false;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	msgstr = argv_concat(argv, argc, 4);
	snprintfrr(leaf, sizeof(leaf), "%s/admin-shutdown/enable", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, "true");
	snprintfrr(leaf, sizeof(leaf), "%s/admin-shutdown/message", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, msgstr);
	XFREE(MTYPE_TMP, msgstr);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_neighbor_shutdown_msg_yang, no_neighbor_shutdown_msg_yang_cmd,
	   "no neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor shutdown message MSG...",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Administratively shut down this neighbor\n"
	   "Remove a shutdown message (RFC 8203)\n"
	   "Shutdown message\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	snprintfrr(leaf, sizeof(leaf), "%s/admin-shutdown/message", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/admin-shutdown/enable", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, "false");
	return nb_cli_apply_changes(vty, NULL);
}


DEFPY_YANG(neighbor_update_source_yang, neighbor_update_source_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor update-source <A.B.C.D|X:X::X:X|WORD>$source",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Source of routing updates\n"
	   "IPv4 address\n"
	   "IPv6 address\n"
	   "Interface name (requires zebra to be running)\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	union sockunion su;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	snprintfrr(leaf, sizeof(leaf), "%s/update-source/ip", xpath);
	if (no) {
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
		snprintfrr(leaf, sizeof(leaf), "%s/update-source/interface", xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	} else if (str2sockunion(source, &su) >= 0) {
		snprintfrr(leaf, sizeof(leaf), "%s/update-source/interface", xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
		snprintfrr(leaf, sizeof(leaf), "%s/update-source/ip", xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, source);
	} else {
		snprintfrr(leaf, sizeof(leaf), "%s/update-source/ip", xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
		snprintfrr(leaf, sizeof(leaf), "%s/update-source/interface", xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, source);
	}

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_neighbor_update_source_yang, no_neighbor_update_source_yang_cmd,
	   "no neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor update-source",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Source of routing updates\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	snprintfrr(leaf, sizeof(leaf), "%s/update-source/ip", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/update-source/interface", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_ebgp_multihop_yang, neighbor_ebgp_multihop_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor ebgp-multihop [(1-255)$ttl]",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Allow EBGP neighbors not on directly connected networks\n"
	   "maximum hop count\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	char buf[16];
	bool is_pg = false;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	snprintfrr(leaf, sizeof(leaf), "%s/ebgp-multihop/enabled", xpath);
	if (no) {
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
		snprintfrr(leaf, sizeof(leaf), "%s/ebgp-multihop/multihop-ttl", xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	} else if (ttl_str) {
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
		snprintfrr(buf, sizeof(buf), "%" PRId64, ttl);
		snprintfrr(leaf, sizeof(leaf), "%s/ebgp-multihop/multihop-ttl", xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, buf);
	} else {
		snprintfrr(leaf, sizeof(leaf), "%s/ebgp-multihop/multihop-ttl", xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
		snprintfrr(leaf, sizeof(leaf), "%s/ebgp-multihop/enabled", xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, "true");
	}

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_disable_connected_check_yang,
	   neighbor_disable_connected_check_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor <disable-connected-check|enforce-multihop>",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "one-hop away EBGP peer using loopback address\n"
	   "Enforce EBGP neighbors perform multihop\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	snprintfrr(leaf, sizeof(leaf), "%s/ebgp-multihop/disable-connected-check", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_ttl_security_yang, neighbor_ttl_security_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor ttl-security hops [(1-254)$hops]",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "BGP ttl-security parameters\n"
	   "Specify the maximum number of hops to the BGP peer\n"
	   "Number of hops to BGP peer\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	char buf[16];
	bool is_pg = false;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	snprintfrr(leaf, sizeof(leaf), "%s/ttl-security", xpath);
	if (no)
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	else {
		if (!hops_str) {
			vty_out(vty, "%% Incomplete command\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		snprintfrr(buf, sizeof(buf), "%" PRId64, hops);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, buf);
	}
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_local_as_yang, neighbor_local_as_yang_cmd,
	   "neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor local-as ASNUM$as_str [no-prepend$noprepend [replace-as$replaceas [dual-as$dualas]]]",
	   NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Specify a local-as number\n"
	   "AS number expressed in dotted or plain format used as local AS\n"
	   "Do not prepend local-as to updates from ebgp peers\n"
	   "Do not prepend local-as to updates from ibgp peers\n"
	   "Allow peering with either global AS or local-as\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	snprintfrr(leaf, sizeof(leaf), "%s/local-as/local-as", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, as_str_str);
	snprintfrr(leaf, sizeof(leaf), "%s/local-as/no-prepend", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, noprepend ? "true" : "false");
	snprintfrr(leaf, sizeof(leaf), "%s/local-as/replace-as", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, replaceas ? "true" : "false");
	snprintfrr(leaf, sizeof(leaf), "%s/local-as/dual-as", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, dualas ? "true" : "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_neighbor_local_as_yang, no_neighbor_local_as_yang_cmd,
	   "no neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor local-as [ASNUM [no-prepend [replace-as] [dual-as]]]",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Specify a local-as number\n"
	   "AS number expressed in dotted or plain format used as local AS\n"
	   "Do not prepend local-as to updates from ebgp peers\n"
	   "Do not prepend local-as to updates from ibgp peers\n"
	   "Allow peering with either global AS or local-as\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	snprintfrr(leaf, sizeof(leaf), "%s/local-as/dual-as", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/local-as/replace-as", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/local-as/no-prepend", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/local-as/local-as", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_timers_yang, neighbor_timers_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor timers [(0-65535)$keepalive (0-65535)$holdtime]",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "BGP per neighbor timers\n"
	   "Keepalive interval\n"
	   "Holdtime\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	char ka_buf[16];
	char ht_buf[16];
	bool is_pg = false;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	if (no) {
		snprintfrr(leaf, sizeof(leaf), "%s/timers/keepalive", xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
		snprintfrr(leaf, sizeof(leaf), "%s/timers/hold-time", xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	} else {
		if (!keepalive_str || !holdtime_str) {
			vty_out(vty, "%% Incomplete command\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		if (!bgp_cli_holdtime_valid(holdtime)) {
			vty_out(vty, "%% hold time value must be either 0 or at least 3\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		/*
		 * nb_cli_enqueue_change() keeps the value pointer. Separate
		 * buffers so keepalive is not overwritten by hold-time.
		 */
		snprintfrr(ka_buf, sizeof(ka_buf), "%" PRId64, keepalive);
		snprintfrr(leaf, sizeof(leaf), "%s/timers/keepalive", xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, ka_buf);
		snprintfrr(ht_buf, sizeof(ht_buf), "%" PRId64, holdtime);
		snprintfrr(leaf, sizeof(leaf), "%s/timers/hold-time", xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, ht_buf);
	}
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_timers_connect_yang, neighbor_timers_connect_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor timers connect [(1-65535)$connect]",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "BGP per neighbor timers\n"
	   "BGP connect timer\n"
	   "Connect timer\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	char buf[16];
	bool is_pg = false;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	snprintfrr(leaf, sizeof(leaf), "%s/timers/connect-time", xpath);
	if (no)
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	else {
		if (!connect_str) {
			vty_out(vty, "%% Incomplete command\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		snprintfrr(buf, sizeof(buf), "%" PRId64, connect);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, buf);
	}
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_timers_delayopen_yang, neighbor_timers_delayopen_yang_cmd,
	   "neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor timers delayopen (1-240)$delayopen",
	   NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "BGP per neighbor timers\n"
	   "BGP DelayOpenTimer\n"
	   "DelayOpenTimer interval in seconds\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	char buf[16];
	bool is_pg = false;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	snprintfrr(leaf, sizeof(leaf), "%s/timers/delayopen", xpath);
	snprintfrr(buf, sizeof(buf), "%" PRId64, delayopen);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, buf);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_neighbor_timers_delayopen_yang, no_neighbor_timers_delayopen_yang_cmd,
	   "no neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor timers delayopen [(0-65535)]",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "BGP per neighbor timers\n"
	   "BGP DelayOpenTimer\n"
	   "DelayOpenTimer interval in seconds\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	snprintfrr(leaf, sizeof(leaf), "%s/timers/delayopen", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_advertise_interval_yang,
	   neighbor_advertise_interval_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor advertisement-interval [(0-600)$interval]",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Minimum interval between sending BGP routing updates\n"
	   "time in seconds\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	char buf[16];
	bool is_pg = false;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	snprintfrr(leaf, sizeof(leaf), "%s/timers/advertise-interval", xpath);
	if (no)
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	else {
		if (!interval_str) {
			vty_out(vty, "%% Incomplete command\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		snprintfrr(buf, sizeof(buf), "%" PRId64, interval);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, buf);
	}
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_capability_dynamic_yang,
	   neighbor_capability_dynamic_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor capability dynamic",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Advertise capability to the peer\n"
	   "Advertise dynamic capability to this neighbor\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	snprintfrr(leaf, sizeof(leaf), "%s/capability-options/dynamic-capability", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_capability_enhe_yang, neighbor_capability_enhe_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor capability extended-nexthop",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Advertise capability to the peer\n"
	   "Advertise extended next-hop capability to the peer\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	snprintfrr(leaf, sizeof(leaf), "%s/capability-options/extended-nexthop-capability", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_dont_capability_negotiate_yang,
	   neighbor_dont_capability_negotiate_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor dont-capability-negotiate",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Do not perform capability negotiation\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	/* YANG capability-negotiate true => negotiate (clear DONT_CAPABILITY) */
	snprintfrr(leaf, sizeof(leaf), "%s/capability-options/capability-negotiate", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, no ? "true" : "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_capability_fqdn_yang, neighbor_capability_fqdn_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor capability fqdn",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Advertise capability to the peer\n"
	   "Advertise fqdn capability to the peer\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	snprintfrr(leaf, sizeof(leaf), "%s/capability-options/fqdn-capability", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_enforce_first_as_yang, neighbor_enforce_first_as_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor enforce-first-as",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Enforce the first AS for EBGP routes\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	snprintfrr(leaf, sizeof(leaf), "%s/enforce-first-as", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}


DEFPY_YANG(neighbor_capability_software_version_yang,
	   neighbor_capability_software_version_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor capability software-version [latest-encoding$latest_encoding]",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Advertise capability to the peer\n"
	   "Advertise Software Version capability to the peer\n"
	   "Use the latest-encoding defined in draft-abraitis-bgp-version-capability-15\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	const char *val;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	if (no)
		val = "disabled";
	else if (latest_encoding)
		val = "latest-encoding";
	else
		val = "old-encoding";

	snprintfrr(leaf, sizeof(leaf), "%s/capability-options/software-version-capability", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, val);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_capability_link_local_yang,
	   neighbor_capability_link_local_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor capability link-local",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Advertise capability to the peer\n"
	   "Advertise Link-Local Next Hop capability to the peer\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	snprintfrr(leaf, sizeof(leaf), "%s/capability-options/link-local-capability", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_override_capability_yang,
	   neighbor_override_capability_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor override-capability",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Override capability negotiation result\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	snprintfrr(leaf, sizeof(leaf), "%s/capability-options/override-capability", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_strict_capability_yang,
	   neighbor_strict_capability_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor strict-capability-match",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Strict capability negotiation match\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	snprintfrr(leaf, sizeof(leaf), "%s/capability-options/strict-capability", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_tcp_mss_yang, neighbor_tcp_mss_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor tcp-mss [(1-65535)$mss]",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "TCP max segment size\n"
	   "TCP MSS value\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	char buf[16];
	bool is_pg = false;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	snprintfrr(leaf, sizeof(leaf), "%s/tcp-mss", xpath);
	if (no)
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	else {
		if (!mss_str) {
			vty_out(vty, "%% Incomplete command\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		snprintfrr(buf, sizeof(buf), "%" PRId64, mss);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, buf);
	}
	vty_out(vty, " Warning: Reset BGP session for tcp-mss value to take effect\n");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_ip_transparent_yang, neighbor_ip_transparent_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor ip-transparent",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Enable IP_TRANSPARENT on the BGP TCP socket\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	snprintfrr(leaf, sizeof(leaf), "%s/ip-transparent", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_rpki_strict_yang, neighbor_rpki_strict_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor rpki strict",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "RPKI configuration\n"
	   "Strict mode\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	snprintfrr(leaf, sizeof(leaf), "%s/rpki-strict", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_local_role_yang, neighbor_local_role_yang_cmd,
	   "neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor local-role <provider|rs-server|rs-client|customer|peer>$role [strict-mode$strict]",
	   NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Set session role\n"
	   "Local speaker provides transit to the remote peer\n"
	   "Local speaker is a route server for the remote peer\n"
	   "Local speaker is a route server client\n"
	   "Local speaker receives transit from the remote peer\n"
	   "Local speaker and remote peer have a lateral peering relationship\n"
	   "Use additional restriction on peer\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	snprintfrr(leaf, sizeof(leaf), "%s/local-role/role", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, role);
	snprintfrr(leaf, sizeof(leaf), "%s/local-role/strict-mode", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, strict ? "true" : "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_neighbor_local_role_yang, no_neighbor_local_role_yang_cmd,
	   "no neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor local-role <provider|rs-server|rs-client|customer|peer> [strict-mode]",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Set session role\n"
	   "Local speaker provides transit to the remote peer\n"
	   "Local speaker is a route server for the remote peer\n"
	   "Local speaker is a route server client\n"
	   "Local speaker receives transit from the remote peer\n"
	   "Local speaker and remote peer have a lateral peering relationship\n"
	   "Use additional restriction on peer\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	snprintfrr(leaf, sizeof(leaf), "%s/local-role/strict-mode", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/local-role/role", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}


DEFPY_YANG(neighbor_bfd_yang, neighbor_bfd_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor bfd",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Enables BFD support\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	snprintfrr(leaf, sizeof(leaf), "%s/bfd-options/enable", xpath);
	if (no) {
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
		snprintfrr(leaf, sizeof(leaf), "%s/bfd-options/detect-multiplier", xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
		snprintfrr(leaf, sizeof(leaf), "%s/bfd-options/required-min-rx", xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
		snprintfrr(leaf, sizeof(leaf), "%s/bfd-options/desired-min-tx", xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
		snprintfrr(leaf, sizeof(leaf), "%s/bfd-options/profile", xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
		snprintfrr(leaf, sizeof(leaf), "%s/bfd-options/check-cp-failure", xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
		snprintfrr(leaf, sizeof(leaf), "%s/bfd-options/strict-hold-time", xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
		snprintfrr(leaf, sizeof(leaf), "%s/bfd-options/strict-mode", xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	} else
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_bfd_param_yang, neighbor_bfd_param_yang_cmd,
	   "neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor bfd (2-255)$detect (50-60000)$min_rx (50-60000)$min_tx",
	   NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Enables BFD support\n"
	   "Detect Multiplier\n"
	   "Required min receive interval\n"
	   "Desired min transmit interval\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	char buf[16];
	bool is_pg = false;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	snprintfrr(leaf, sizeof(leaf), "%s/bfd-options/enable", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, "true");
	snprintfrr(buf, sizeof(buf), "%" PRId64, detect);
	snprintfrr(leaf, sizeof(leaf), "%s/bfd-options/detect-multiplier", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, buf);
	snprintfrr(buf, sizeof(buf), "%" PRId64, min_rx);
	snprintfrr(leaf, sizeof(leaf), "%s/bfd-options/required-min-rx", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, buf);
	snprintfrr(buf, sizeof(buf), "%" PRId64, min_tx);
	snprintfrr(leaf, sizeof(leaf), "%s/bfd-options/desired-min-tx", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, buf);
	return nb_cli_apply_changes(vty, NULL);
}

ALIAS_ATTR(neighbor_bfd_yang, no_neighbor_bfd_param_yang_cmd,
	   "no neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor bfd (2-255) (50-60000) (50-60000)",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Enables BFD support\n"
	   "Detect Multiplier\n"
	   "Required min receive interval\n"
	   "Desired min transmit interval\n",
	   CMD_ATTR_YANG);

DEFPY_YANG(neighbor_bfd_profile_yang, neighbor_bfd_profile_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor bfd profile [BFDPROF$profile]",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "BFD integration\n"
	   BFD_PROFILE_STR
	   BFD_PROFILE_NAME_STR)
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	snprintfrr(leaf, sizeof(leaf), "%s/bfd-options/profile", xpath);
	if (no)
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	else {
		if (!profile) {
			vty_out(vty, "%% Incomplete command\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		snprintfrr(leaf, sizeof(leaf), "%s/bfd-options/enable", xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, "true");
		snprintfrr(leaf, sizeof(leaf), "%s/bfd-options/profile", xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, profile);
	}
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_bfd_cbit_yang, neighbor_bfd_cbit_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor bfd check-control-plane-failure",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "BFD support\n"
	   "Link dataplane status with BGP controlplane\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	if (!no) {
		snprintfrr(leaf, sizeof(leaf), "%s/bfd-options/enable", xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, "true");
	}
	snprintfrr(leaf, sizeof(leaf), "%s/bfd-options/check-cp-failure", xpath);
	/*
	 * Setting the leaf to false requires enable = true. Destroy clears
	 * cbit whether or not BFD is configured on the neighbor.
	 */
	if (no)
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_bfd_strict_yang, neighbor_bfd_strict_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor bfd strict",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "BFD support\n"
	   "Strict mode\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	snprintfrr(leaf, sizeof(leaf), "%s/bfd-options/strict-mode", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_bfd_strict_hold_yang, neighbor_bfd_strict_hold_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor bfd strict hold-time ![(1-4294967295)$hold_time]",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "BFD support\n"
	   "Strict mode\n"
	   "BFD Hold time in seconds\n"
	   "Seconds to wait before declaring BFD session down\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	char buf[16];
	bool is_pg = false;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	snprintfrr(leaf, sizeof(leaf), "%s/bfd-options/strict-hold-time", xpath);
	if (no) {
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
		snprintfrr(leaf, sizeof(leaf), "%s/bfd-options/strict-mode", xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, "false");
	} else {
		snprintfrr(leaf, sizeof(leaf), "%s/bfd-options/enable", xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, "true");
		snprintfrr(leaf, sizeof(leaf), "%s/bfd-options/strict-mode", xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, "true");
		snprintfrr(buf, sizeof(buf), "%" PRId64, hold_time);
		snprintfrr(leaf, sizeof(leaf), "%s/bfd-options/strict-hold-time", xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, buf);
	}
	return nb_cli_apply_changes(vty, NULL);
}


static void bgp_cli_path_attr_release(char **attributes, int num_attributes)
{
	int i;

	if (!attributes)
		return;
	for (i = 0; i < num_attributes; i++)
		XFREE(MTYPE_TMP, attributes[i]);
	XFREE(MTYPE_TMP, attributes);
}

/*
 * nb_cli_enqueue_change() stores the value pointer and does not copy it.
 * Split tokens handed to NB_OP_CREATE must stay alive until apply returns.
 * The lookup xpath is absolute: base is relative (./neighbors/...), and
 * prefixing only VTY_CURR_XPATH looks up the BGP instance instead of the peer.
 */
static void bgp_cli_path_attr_enqueue_replace(struct vty *vty, const char *base,
					      const char *leaf_name, const char *attrs, bool set,
					      char ***held, int *nheld)
{
	char leaf[XPATH_MAXLEN + 256];
	char check[XPATH_MAXLEN + 256];
	char **attributes = NULL;
	int num_attributes = 0;
	int i;

	if (held)
		*held = NULL;
	if (nheld)
		*nheld = 0;

	if (base[0] == '.')
		snprintfrr(check, sizeof(check), "%s%s/path-attribute/%s", VTY_CURR_XPATH,
			   base + 1, leaf_name);
	else
		snprintfrr(check, sizeof(check), "%s/path-attribute/%s", base, leaf_name);
	/* Replace semantics on set: clear existing entries first. */
	if (set || !attrs) {
		const struct lyd_node *dnode = yang_dnode_get(vty->candidate_config->dnode, check);
		const struct lyd_node *parent, *child, *next;

		if (dnode) {
			parent = lyd_parent(dnode);
			for (child = lyd_child(parent); child; child = next) {
				next = child->next;
				if (child->schema->nodetype != LYS_LEAFLIST)
					continue;
				if (!strmatch(child->schema->name, leaf_name))
					continue;
				snprintfrr(leaf, sizeof(leaf), "%s/path-attribute/%s[.='%s']",
					   base, leaf_name, yang_dnode_get_string(child, NULL));
				nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
			}
		}
	}

	if (!attrs)
		return;

	frrstr_split(attrs, " ", &attributes, &num_attributes);
	for (i = 0; i < num_attributes; i++) {
		snprintfrr(leaf, sizeof(leaf), "%s/path-attribute/%s[.='%s']", base, leaf_name,
			   attributes[i]);
		if (set)
			nb_cli_enqueue_change(vty, leaf, NB_OP_CREATE, attributes[i]);
		else
			nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	}
	if (held && nheld) {
		*held = attributes;
		*nheld = num_attributes;
	} else
		bgp_cli_path_attr_release(attributes, num_attributes);
}

DEFPY_YANG(neighbor_path_attribute_discard_yang,
	   neighbor_path_attribute_discard_yang_cmd,
	   "neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor path-attribute discard (1-255)...",
	   NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Manipulate path attributes from incoming UPDATE messages\n"
	   "Drop specified attributes from incoming UPDATE messages\n"
	   "Attribute number\n")
{
	char xpath[XPATH_MAXLEN];
	bool is_pg = false;
	char *attrs;
	char **held = NULL;
	int nheld = 0;
	int idx = 0;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	argv_find(argv, argc, "(1-255)", &idx);
	attrs = idx ? argv_concat(argv, argc, idx) : NULL;
	bgp_cli_path_attr_enqueue_replace(vty, xpath, "discard", attrs, true, &held, &nheld);
	XFREE(MTYPE_TMP, attrs);
	ret = nb_cli_apply_changes(vty, NULL);
	bgp_cli_path_attr_release(held, nheld);
	return ret;
}

DEFPY_YANG(no_neighbor_path_attribute_discard_yang,
	   no_neighbor_path_attribute_discard_yang_cmd,
	   "no neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor path-attribute discard [(1-255)]",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Manipulate path attributes from incoming UPDATE messages\n"
	   "Drop specified attributes from incoming UPDATE messages\n"
	   "Attribute number\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	int idx = 0;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	argv_find(argv, argc, "(1-255)", &idx);
	if (idx) {
		snprintfrr(leaf, sizeof(leaf), "%s/path-attribute/discard[.='%s']", xpath,
			   argv[idx]->arg);
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	} else
		bgp_cli_path_attr_enqueue_replace(vty, xpath, "discard", NULL, false, NULL, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_path_attribute_withdraw_yang,
	   neighbor_path_attribute_withdraw_yang_cmd,
	   "neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor path-attribute treat-as-withdraw (1-255)...",
	   NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Manipulate path attributes from incoming UPDATE messages\n"
	   "Treat-as-withdraw any incoming BGP UPDATE messages that contain the specified attribute\n"
	   "Attribute number\n")
{
	char xpath[XPATH_MAXLEN];
	bool is_pg = false;
	char *attrs;
	char **held = NULL;
	int nheld = 0;
	int idx = 0;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	argv_find(argv, argc, "(1-255)", &idx);
	attrs = idx ? argv_concat(argv, argc, idx) : NULL;
	bgp_cli_path_attr_enqueue_replace(vty, xpath, "treat-as-withdraw", attrs, true, &held,
					  &nheld);
	XFREE(MTYPE_TMP, attrs);
	ret = nb_cli_apply_changes(vty, NULL);
	bgp_cli_path_attr_release(held, nheld);
	return ret;
}

DEFPY_YANG(no_neighbor_path_attribute_withdraw_yang,
	   no_neighbor_path_attribute_withdraw_yang_cmd,
	   "no neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor path-attribute treat-as-withdraw (1-255)...",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Manipulate path attributes from incoming UPDATE messages\n"
	   "Treat-as-withdraw any incoming BGP UPDATE messages that contain the specified attribute\n"
	   "Attribute number\n")
{
	char xpath[XPATH_MAXLEN];
	bool is_pg = false;
	char *attrs;
	char **held = NULL;
	int nheld = 0;
	int idx = 0;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	argv_find(argv, argc, "(1-255)", &idx);
	attrs = idx ? argv_concat(argv, argc, idx) : NULL;
	bgp_cli_path_attr_enqueue_replace(vty, xpath, "treat-as-withdraw", attrs, false, &held,
					  &nheld);
	XFREE(MTYPE_TMP, attrs);
	ret = nb_cli_apply_changes(vty, NULL);
	bgp_cli_path_attr_release(held, nheld);
	return ret;
}

static int bgp_cli_peer_gr_mode(struct vty *vty, const char *neighbor, const char *mode_leaf,
				bool enable)
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	/* Choice: clear other modes when enabling one. */
	snprintfrr(leaf, sizeof(leaf), "%s/graceful-restart/enable", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/graceful-restart/graceful-restart-helper", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/graceful-restart/graceful-restart-disable", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);

	if (enable) {
		snprintfrr(leaf, sizeof(leaf), "%s/graceful-restart/%s", xpath, mode_leaf);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, "true");
	}

	ret = nb_cli_apply_changes(vty, NULL);
	if (ret == CMD_SUCCESS)
		vty_out(vty,
			"Graceful restart configuration changed, reset this peer to take effect\n");
	return ret;
}

DEFPY_YANG(neighbor_graceful_restart_yang, neighbor_graceful_restart_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor graceful-restart",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Graceful restart capability on this neighbor\n")
{
	return bgp_cli_peer_gr_mode(vty, neighbor, "enable", !no);
}

DEFPY_YANG(neighbor_graceful_restart_helper_yang,
	   neighbor_graceful_restart_helper_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor graceful-restart-helper",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Graceful restart helper mode capability on this neighbor\n")
{
	return bgp_cli_peer_gr_mode(vty, neighbor, "graceful-restart-helper", !no);
}

DEFPY_YANG(neighbor_graceful_restart_disable_yang,
	   neighbor_graceful_restart_disable_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor graceful-restart-disable",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Disable graceful restart and helper mode on this neighbor\n")
{
	return bgp_cli_peer_gr_mode(vty, neighbor, "graceful-restart-disable", !no);
}

DEFPY_YANG(neighbor_aigp_yang, neighbor_aigp_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor aigp",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Enable send and receive of the AIGP attribute per neighbor\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	snprintfrr(leaf, sizeof(leaf), "%s/aigp", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_oad_yang, neighbor_oad_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor oad",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Set peering session type to EBGP-OAD\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	snprintfrr(leaf, sizeof(leaf), "%s/oad", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_graceful_shutdown_yang, neighbor_graceful_shutdown_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor graceful-shutdown",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Graceful shutdown\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	snprintfrr(leaf, sizeof(leaf), "%s/graceful-shutdown", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, no ? "false" : "true");
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

	install_element(BGP_NODE, &bgp_cluster_id_yang_cmd);
	install_element(BGP_NODE, &no_bgp_cluster_id_yang_cmd);
	install_element(BGP_NODE, &bgp_client_to_client_reflection_yang_cmd);
	install_element(BGP_NODE, &no_bgp_client_to_client_reflection_yang_cmd);
	install_element(BGP_NODE, &bgp_always_compare_med_yang_cmd);
	install_element(BGP_NODE, &no_bgp_always_compare_med_yang_cmd);
	install_element(BGP_NODE, &bgp_deterministic_med_yang_cmd);
	install_element(BGP_NODE, &no_bgp_deterministic_med_yang_cmd);
	install_element(BGP_NODE, &bgp_default_local_preference_yang_cmd);
	install_element(BGP_NODE, &no_bgp_default_local_preference_yang_cmd);
	install_element(BGP_NODE, &bgp_fast_external_failover_yang_cmd);
	install_element(BGP_NODE, &no_bgp_fast_external_failover_yang_cmd);
	install_element(BGP_NODE, &bgp_suppress_duplicates_yang_cmd);
	install_element(BGP_NODE, &no_bgp_suppress_duplicates_yang_cmd);
	install_element(BGP_NODE, &bgp_graceful_shutdown_yang_cmd);
	install_element(BGP_NODE, &no_bgp_graceful_shutdown_yang_cmd);
	install_element(BGP_NODE, &bgp_reject_as_sets_yang_cmd);
	install_element(BGP_NODE, &no_bgp_reject_as_sets_yang_cmd);

	install_element(BGP_NODE, &bgp_enforce_first_as_yang_cmd);
	install_element(BGP_NODE, &bgp_disable_connected_route_check_yang_cmd);
	install_element(BGP_NODE, &no_bgp_disable_connected_route_check_yang_cmd);
	install_element(BGP_NODE, &bgp_rr_allow_outbound_policy_yang_cmd);
	install_element(BGP_NODE, &no_bgp_rr_allow_outbound_policy_yang_cmd);
	install_element(BGP_NODE, &bgp_administrative_reset_yang_cmd);
	install_element(BGP_NODE, &bgp_default_show_hostname_yang_cmd);
	install_element(BGP_NODE, &no_bgp_default_show_hostname_yang_cmd);
	install_element(BGP_NODE, &bgp_default_show_nexthop_hostname_yang_cmd);
	install_element(BGP_NODE, &no_bgp_default_show_nexthop_hostname_yang_cmd);
	install_element(BGP_NODE, &bgp_bestpath_compare_router_id_yang_cmd);
	install_element(BGP_NODE, &no_bgp_bestpath_compare_router_id_yang_cmd);
	install_element(BGP_NODE, &bgp_bestpath_aspath_ignore_yang_cmd);
	install_element(BGP_NODE, &no_bgp_bestpath_aspath_ignore_yang_cmd);

	install_element(BGP_NODE, &bgp_bestpath_aigp_yang_cmd);
	install_element(BGP_NODE, &bgp_bestpath_use_imported_attrs_yang_cmd);
	install_element(BGP_NODE, &bgp_bestpath_prefer_mpls_over_srv6_yang_cmd);
	install_element(BGP_NODE, &bgp_bestpath_aspath_confed_yang_cmd);
	install_element(BGP_NODE, &no_bgp_bestpath_aspath_confed_yang_cmd);
	install_element(BGP_NODE, &bgp_bestpath_aspath_multipath_relax_yang_cmd);
	install_element(BGP_NODE, &no_bgp_bestpath_aspath_multipath_relax_yang_cmd);
	install_element(BGP_NODE, &bgp_bestpath_peer_type_multipath_relax_yang_cmd);
	install_element(BGP_NODE, &no_bgp_bestpath_peer_type_multipath_relax_yang_cmd);
	install_element(BGP_NODE, &bgp_bestpath_med_yang_cmd);
	install_element(BGP_NODE, &no_bgp_bestpath_med_yang_cmd);
	install_element(BGP_NODE, &bgp_bestpath_bw_yang_cmd);
	install_element(BGP_NODE, &no_bgp_bestpath_bw_yang_cmd);

	install_element(BGP_NODE, &bgp_timers_yang_cmd);
	install_element(BGP_NODE, &no_bgp_timers_yang_cmd);
	install_element(BGP_NODE, &bgp_minimum_holdtime_yang_cmd);
	install_element(BGP_NODE, &no_bgp_minimum_holdtime_yang_cmd);
	install_element(BGP_NODE, &bgp_confederation_identifier_yang_cmd);
	install_element(BGP_NODE, &no_bgp_confederation_identifier_yang_cmd);
	install_element(BGP_NODE, &bgp_confederation_peers_yang_cmd);
	install_element(BGP_NODE, &no_bgp_confederation_peers_yang_cmd);
	install_element(BGP_NODE, &bgp_maxmed_admin_yang_cmd);
	install_element(BGP_NODE, &bgp_maxmed_admin_medv_yang_cmd);
	install_element(BGP_NODE, &no_bgp_maxmed_admin_yang_cmd);
	install_element(BGP_NODE, &bgp_maxmed_onstartup_yang_cmd);
	install_element(BGP_NODE, &no_bgp_maxmed_onstartup_yang_cmd);
	install_element(BGP_NODE, &bgp_update_delay_yang_cmd);
	install_element(BGP_NODE, &no_bgp_update_delay_yang_cmd);
	install_element(BGP_NODE, &bgp_advertisement_delay_yang_cmd);
	install_element(BGP_NODE, &no_bgp_advertisement_delay_yang_cmd);

	install_element(BGP_NODE, &bgp_listen_limit_yang_cmd);
	install_element(BGP_NODE, &no_bgp_listen_limit_yang_cmd);
	install_element(BGP_NODE, &bgp_default_afi_safi_yang_cmd);
	install_element(BGP_NODE, &bgp_graceful_restart_stalepath_time_yang_cmd);
	install_element(BGP_NODE, &no_bgp_graceful_restart_stalepath_time_yang_cmd);
	install_element(BGP_NODE, &bgp_graceful_restart_restart_time_yang_cmd);
	install_element(BGP_NODE, &no_bgp_graceful_restart_restart_time_yang_cmd);
	install_element(BGP_NODE, &bgp_graceful_restart_select_defer_time_yang_cmd);
	install_element(BGP_NODE, &no_bgp_graceful_restart_select_defer_time_yang_cmd);
	install_element(BGP_NODE, &bgp_graceful_restart_rib_stale_time_yang_cmd);
	install_element(BGP_NODE, &no_bgp_graceful_restart_rib_stale_time_yang_cmd);
	install_element(BGP_NODE, &bgp_graceful_restart_preserve_fw_yang_cmd);
	install_element(BGP_NODE, &no_bgp_graceful_restart_preserve_fw_yang_cmd);
	install_element(BGP_NODE, &bgp_graceful_restart_notification_yang_cmd);
	install_element(BGP_NODE, &bgp_graceful_restart_disable_eor_yang_cmd);
	install_element(BGP_NODE, &no_bgp_graceful_restart_disable_eor_yang_cmd);
	install_element(BGP_NODE, &bgp_llgr_stalepath_time_yang_cmd);
	install_element(BGP_NODE, &no_bgp_llgr_stalepath_time_yang_cmd);

	install_element(BGP_NODE, &bgp_graceful_restart_yang_cmd);
	install_element(BGP_NODE, &no_bgp_graceful_restart_yang_cmd);
	install_element(BGP_NODE, &bgp_graceful_restart_disable_yang_cmd);
	install_element(BGP_NODE, &no_bgp_graceful_restart_disable_yang_cmd);
	install_element(BGP_NODE, &bgp_tcp_keepalive_yang_cmd);
	install_element(BGP_NODE, &no_bgp_tcp_keepalive_yang_cmd);
	install_element(BGP_NODE, &bgp_wpkt_quanta_yang_cmd);
	install_element(BGP_NODE, &bgp_rpkt_quanta_yang_cmd);
	install_element(BGP_NODE, &bgp_coalesce_time_yang_cmd);
	install_element(BGP_NODE, &no_bgp_coalesce_time_yang_cmd);
	install_element(BGP_NODE, &bgp_default_subgroup_pkt_queue_max_yang_cmd);
	install_element(BGP_NODE, &no_bgp_default_subgroup_pkt_queue_max_yang_cmd);
	install_element(BGP_NODE, &bgp_default_shutdown_yang_cmd);
	install_element(BGP_NODE, &bgp_shutdown_yang_cmd);
	install_element(BGP_NODE, &bgp_shutdown_msg_yang_cmd);
	install_element(BGP_NODE, &bgp_shutdown_no_notify_yang_cmd);
	install_element(BGP_NODE, &no_bgp_shutdown_yang_cmd);
	install_element(BGP_NODE, &no_bgp_shutdown_msg_yang_cmd);
	install_element(BGP_NODE, &no_bgp_shutdown_no_notify_yang_cmd);
	install_element(BGP_NODE, &bgp_allow_martian_yang_cmd);
	install_element(BGP_NODE, &bgp_use_underlying_nexthop_weight_yang_cmd);

	install_element(BGP_NODE, &bgp_suppress_fib_pending_yang_cmd);
	install_element(BGP_NODE, &bgp_fast_convergence_yang_cmd);
	install_element(BGP_NODE, &no_bgp_fast_convergence_yang_cmd);
	install_element(BGP_NODE, &bgp_ipv6_auto_ra_yang_cmd);
	install_element(BGP_NODE, &bgp_lu_uses_explicit_null_yang_cmd);
	install_element(BGP_NODE, &bgp_default_dynamic_capability_yang_cmd);
	install_element(BGP_NODE, &bgp_default_link_local_capability_yang_cmd);
	install_element(BGP_NODE, &bgp_default_software_version_capability_yang_cmd);

	install_element(BGP_NODE, &neighbor_peer_group_yang_cmd);
	install_element(BGP_NODE, &neighbor_remote_as_yang_cmd);
	install_element(BGP_NODE, &no_neighbor_yang_cmd);
	install_element(BGP_NODE, &no_neighbor_remote_as_yang_cmd);
	install_element(BGP_NODE, &neighbor_interface_config_yang_cmd);
	install_element(BGP_NODE, &neighbor_interface_peer_group_yang_cmd);
	install_element(BGP_NODE, &neighbor_interface_remote_as_yang_cmd);
	install_element(BGP_NODE, &no_neighbor_interface_config_yang_cmd);
	install_element(BGP_NODE, &neighbor_password_yang_cmd);
	install_element(BGP_NODE, &neighbor_description_yang_cmd);
	install_element(BGP_NODE, &no_neighbor_description_yang_cmd);
	install_element(BGP_NODE, &no_neighbor_description_comment_yang_cmd);
	install_element(BGP_NODE, &neighbor_passive_yang_cmd);
	install_element(BGP_NODE, &neighbor_solo_yang_cmd);
	install_element(BGP_NODE, &neighbor_shutdown_yang_cmd);
	install_element(BGP_NODE, &neighbor_shutdown_msg_yang_cmd);
	install_element(BGP_NODE, &no_neighbor_shutdown_msg_yang_cmd);
	install_element(BGP_NODE, &neighbor_update_source_yang_cmd);
	install_element(BGP_NODE, &no_neighbor_update_source_yang_cmd);
	install_element(BGP_NODE, &neighbor_ebgp_multihop_yang_cmd);
	install_element(BGP_NODE, &neighbor_disable_connected_check_yang_cmd);
	install_element(BGP_NODE, &neighbor_ttl_security_yang_cmd);
	install_element(BGP_NODE, &neighbor_local_as_yang_cmd);
	install_element(BGP_NODE, &no_neighbor_local_as_yang_cmd);
	install_element(BGP_NODE, &neighbor_timers_yang_cmd);
	install_element(BGP_NODE, &neighbor_timers_connect_yang_cmd);
	install_element(BGP_NODE, &neighbor_timers_delayopen_yang_cmd);
	install_element(BGP_NODE, &no_neighbor_timers_delayopen_yang_cmd);
	install_element(BGP_NODE, &neighbor_advertise_interval_yang_cmd);
	install_element(BGP_NODE, &neighbor_capability_dynamic_yang_cmd);
	install_element(BGP_NODE, &neighbor_capability_enhe_yang_cmd);
	install_element(BGP_NODE, &neighbor_dont_capability_negotiate_yang_cmd);
	install_element(BGP_NODE, &neighbor_capability_fqdn_yang_cmd);
	install_element(BGP_NODE, &neighbor_enforce_first_as_yang_cmd);
	install_element(BGP_NODE, &neighbor_capability_software_version_yang_cmd);
	install_element(BGP_NODE, &neighbor_capability_link_local_yang_cmd);
	install_element(BGP_NODE, &neighbor_override_capability_yang_cmd);
	install_element(BGP_NODE, &neighbor_strict_capability_yang_cmd);
	install_element(BGP_NODE, &neighbor_tcp_mss_yang_cmd);
	install_element(BGP_NODE, &neighbor_ip_transparent_yang_cmd);
	install_element(BGP_NODE, &neighbor_rpki_strict_yang_cmd);
	install_element(BGP_NODE, &neighbor_local_role_yang_cmd);
	install_element(BGP_NODE, &no_neighbor_local_role_yang_cmd);
	install_element(BGP_NODE, &neighbor_bfd_yang_cmd);
	install_element(BGP_NODE, &neighbor_bfd_param_yang_cmd);
	install_element(BGP_NODE, &no_neighbor_bfd_param_yang_cmd);
	install_element(BGP_NODE, &neighbor_bfd_profile_yang_cmd);
	install_element(BGP_NODE, &neighbor_bfd_cbit_yang_cmd);
	install_element(BGP_NODE, &neighbor_bfd_strict_yang_cmd);
	install_element(BGP_NODE, &neighbor_bfd_strict_hold_yang_cmd);
	install_element(BGP_NODE, &neighbor_path_attribute_discard_yang_cmd);
	install_element(BGP_NODE, &no_neighbor_path_attribute_discard_yang_cmd);
	install_element(BGP_NODE, &neighbor_path_attribute_withdraw_yang_cmd);
	install_element(BGP_NODE, &no_neighbor_path_attribute_withdraw_yang_cmd);
	install_element(BGP_NODE, &neighbor_graceful_restart_yang_cmd);
	install_element(BGP_NODE, &neighbor_graceful_restart_helper_yang_cmd);
	install_element(BGP_NODE, &neighbor_graceful_restart_disable_yang_cmd);
	install_element(BGP_NODE, &neighbor_aigp_yang_cmd);
	install_element(BGP_NODE, &neighbor_oad_yang_cmd);
	install_element(BGP_NODE, &neighbor_graceful_shutdown_yang_cmd);
}
