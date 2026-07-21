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
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_nb.h"
#include "bgpd/bgp_io.h"
#include "bgpd/bgp_updgrp.h"

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
	nb_cli_enqueue_change(vty, "./global/route-selection-options/allow-multiple-as",
			      NB_OP_MODIFY, "false");
	nb_cli_enqueue_change(vty, "./global/route-selection-options/multi-path-as-set",
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


DEFUN_YANG(bgp_timers_yang, bgp_timers_yang_cmd,
	   "timers bgp (0-65535) (0-65535)",
	   "Adjust routing timers\n"
	   "BGP timers\n"
	   "Keepalive interval\n"
	   "Holdtime\n")
{
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
	nb_cli_enqueue_change(vty, "./global/confederation/identifier", NB_OP_MODIFY, argv[3]->arg);
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

	for (i = 3; i < argc; i++) {
		snprintfrr(xpath, sizeof(xpath), "./global/confederation/member-as[.='%s']",
			   argv[i]->arg);
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
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

	for (i = 4; i < argc; i++) {
		snprintfrr(xpath, sizeof(xpath), "./global/confederation/member-as[.='%s']",
			   argv[i]->arg);
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

	snprintfrr(value, sizeof(value), "%lu", BGP_MAXMED_VALUE_DEFAULT);
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

	snprintfrr(value, sizeof(value), "%lu", BGP_MAXMED_VALUE_DEFAULT);
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

	argv_find(argv, argc, "(5-86400)", &idx);
	nb_cli_enqueue_change(vty, "./global/med-config/max-med-onstart-up-time", NB_OP_MODIFY,
			      argv[idx]->arg);
	idx = 0;
	if (argv_find(argv, argc, "(0-4294967295)", &idx))
		nb_cli_enqueue_change(vty, "./global/med-config/max-med-onstart-up-value",
				      NB_OP_MODIFY, argv[idx]->arg);
	else {
		snprintfrr(value, sizeof(value), "%lu", BGP_MAXMED_VALUE_DEFAULT);
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

	snprintfrr(val, sizeof(val), "%ld", no ? (long)BGP_WRITE_PACKET_MAX : quanta);
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

	snprintfrr(val, sizeof(val), "%ld", no ? (long)BGP_READ_PACKET_MAX : quanta);
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
}
