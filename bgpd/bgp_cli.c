// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP YANG-backed CLI (northbound conversion)
 * Copyright (C) 2026 FRRouting
 */

#include <zebra.h>

#ifdef GNU_LINUX
#include <linux/rtnetlink.h> //RT_TABLE_XXX
#endif

#include "command.h"
#include "northbound_cli.h"
#include "typesafe.h"
#include "vrf.h"
#include "asn.h"
#include "frrstr.h"
#include "bfd.h"
#include "routing_nb.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_nb.h"
#include "bgpd/bgp_io.h"
#include "bgpd/bgp_updgrp.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_damp.h"
#include "bgpd/bgp_evpn.h"
#include "bgpd/bgp_evpn_private.h"
#include "bgpd/bgp_rd.h"
#include "bgpd/bgp_filter_cli.h"
#include "bgpd/bgp_open.h"
#include "bgpd/bgp_packet.h"
#ifdef ENABLE_BGP_VNC
#include "bgpd/bgp_vnc_nb.h"
#endif

#include "bgpd/bgp_cli_clippy.c"

/*
 * Address-family CLI helpers (classic AF nodes keep vty->node; BGP YANG
 * xpath remains on the stack from router bgp).
 */
static const char *bgp_cli_afi_safi_name(int node)
{
	switch (node) {
	case BGP_IPV4_NODE:
		return "ipv4-unicast";
	case BGP_IPV4M_NODE:
		return "ipv4-multicast";
	case BGP_IPV4L_NODE:
		return "ipv4-labeled-unicast";
	case BGP_IPV6_NODE:
		return "ipv6-unicast";
	case BGP_IPV6M_NODE:
		return "ipv6-multicast";
	case BGP_IPV6L_NODE:
		return "ipv6-labeled-unicast";
	case BGP_VPNV4_NODE:
		return "l3vpn-ipv4-unicast";
	case BGP_VPNV6_NODE:
		return "l3vpn-ipv6-unicast";
	case BGP_EVPN_NODE:
		return "l2vpn-evpn";
	case BGP_FLOWSPECV4_NODE:
		return "ipv4-flowspec";
	case BGP_FLOWSPECV6_NODE:
		return "ipv6-flowspec";
	case BGP_LS_NODE:
		return "link-state";
	case BGP_IPV4U_NODE:
		return "ipv4-unreachability";
	case BGP_IPV6U_NODE:
		return "ipv6-unreachability";
	default:
		return "ipv4-unicast";
	}
}

/* Build relative xpath for the current global AFI-SAFI config container.
 * Schema nests AF leaves under afi-safi/<af>/ (e.g. ipv4-unicast), not
 * directly under the afi-safi list entry.
 */
static int bgp_cli_global_af_xpath(struct vty *vty, char *xpath, size_t xpath_len)
{
	const char *af = bgp_cli_afi_safi_name(vty->node);

	snprintfrr(xpath, xpath_len,
		   "./global/afi-safis/afi-safi[afi-safi-name='frr-routing:%s']/%s", af, af);
	return 0;
}

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
	} else {
		/*
		 * Match classic: ASDOT input like "1.300" implies asnotation
		 * dot even without an explicit as-notation keyword.
		 */
		asn_str2asn_notation(argv[2]->arg, NULL, &asnotation);
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

	/*
	 * Seed YANG to match bgp_create()'s default_af IPv4 unicast, but only
	 * for a new instance. Re-entering an existing router must not restore
	 * a previously removed default. Without the leaf, "no bgp default
	 * ipv4-unicast" DESTROY is a no-op and labeled-unicast activate fails.
	 */
	{
		struct bgp *existing;

		if (strmatch(vrf_name, VRF_DEFAULT_NAME))
			existing = bgp_get_default();
		else
			existing = bgp_lookup_by_name(name);
		if (!existing) {
			snprintfrr(leaf_xpath, sizeof(leaf_xpath),
				   "%s/global/default-afi-safi[.='ipv4-unicast']", bgp_xpath);
			nb_cli_enqueue_change(vty, leaf_xpath, NB_OP_CREATE, NULL);
		}
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
	   "no router bgp [ASNUM [<view|vrf> VIEWVRFNAME] [as-notation <dot|dot+|plain>]]",
	   NO_STR ROUTER_STR BGP_STR AS_STR BGP_INSTANCE_HELP_STR
	   "Force the AS notation output style\n"
	   "Ignore as-notation on delete\n"
	   "Ignore as-notation on delete\n"
	   "Ignore as-notation on delete\n")
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

DEFUN_YANG_NOSH(bgp_segment_routing_srv6_yang, bgp_segment_routing_srv6_yang_cmd,
		"segment-routing srv6",
		"Segment-Routing configuration\n"
		"Segment-Routing SRv6 configuration\n")
{
	/* Pure node switch; do not require BGP qobj context (vtysh -f / mgmtd). */
	vty->node = BGP_SRV6_NODE;
	return CMD_SUCCESS;
}

DEFUN_YANG(no_bgp_segment_routing_srv6_yang,
	   no_bgp_segment_routing_srv6_yang_cmd, "no segment-routing srv6",
	   NO_STR
	   "Segment-Routing configuration\n"
	   "Segment-Routing SRv6 configuration\n")
{
	nb_cli_enqueue_change(vty, "./global/segment-routing/srv6/locator", NB_OP_DESTROY, NULL);
	nb_cli_enqueue_change(vty, "./global/segment-routing/srv6/encap-behavior", NB_OP_DESTROY,
			      NULL);
	/* Classic restores srv6-only to its default (true), which is not shown. */
	nb_cli_enqueue_change(vty, "./global/segment-routing/srv6/srv6-only", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_srv6_locator_yang, bgp_srv6_locator_yang_cmd,
	   "locator NAME$name",
	   "Specify SRv6 locator\n"
	   "Specify SRv6 locator\n")
{
	nb_cli_enqueue_change(vty, "./global/segment-routing/srv6/locator", NB_OP_MODIFY, name);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_bgp_srv6_locator_yang, no_bgp_srv6_locator_yang_cmd,
	   "no locator NAME$name",
	   NO_STR
	   "Specify SRv6 locator\n"
	   "Specify SRv6 locator\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	if (strlen(bgp->srv6_locator_name) < 1)
		return CMD_SUCCESS;

	if (!strmatch(name, bgp->srv6_locator_name)) {
		vty_out(vty, "%% No srv6 locator is configured\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	nb_cli_enqueue_change(vty, "./global/segment-routing/srv6/locator", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_srv6_encap_behavior_yang, bgp_srv6_encap_behavior_yang_cmd,
	   "[no$no] encap-behavior <H_Encaps|H_Encaps_Red>$encap_behavior",
	   NO_STR
	   "Configure SRv6 encap mode\n"
	   "H.Encaps\n"
	   "H.Encaps.Red\n")
{
	const char *yang_val;

	if (no) {
		if (strmatch(encap_behavior, "H_Encaps_Red"))
			nb_cli_enqueue_change(vty, "./global/segment-routing/srv6/encap-behavior",
					      NB_OP_DESTROY, NULL);
		else
			return CMD_SUCCESS;
	} else {
		yang_val = strmatch(encap_behavior, "H_Encaps_Red") ? "h-encaps-red" : "h-encaps";
		nb_cli_enqueue_change(vty, "./global/segment-routing/srv6/encap-behavior",
				      NB_OP_MODIFY, yang_val);
	}
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_srv6_only_yang, bgp_srv6_only_yang_cmd, "[no] srv6-only",
	   NO_STR
	   "Only allow SRv6 and disallow MPLS routes\n")
{
	nb_cli_enqueue_change(vty, "./global/segment-routing/srv6/srv6-only", NB_OP_MODIFY,
			      no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

static void bgp_cli_sid_vpn_per_vrf_clear(struct vty *vty)
{
	nb_cli_enqueue_change(vty, "./global/sid-vpn-per-vrf-export/sid-index", NB_OP_DESTROY,
			      NULL);
	nb_cli_enqueue_change(vty, "./global/sid-vpn-per-vrf-export/sid-auto", NB_OP_DESTROY, NULL);
	nb_cli_enqueue_change(vty, "./global/sid-vpn-per-vrf-export/sid-explicit", NB_OP_DESTROY,
			      NULL);
}

DEFPY_YANG(bgp_sid_vpn_export_yang, bgp_sid_vpn_export_yang_cmd,
	   "[no] sid vpn per-vrf export [<(1-4294967295)$sid_idx|auto$sid_auto|explicit$sid_explicit X:X::X:X$sid_value>]",
	   NO_STR
	   "sid value for VRF\n"
	   "Between current vrf and vpn\n"
	   "sid per-VRF (both IPv4 and IPv6 address families)\n"
	   "For routes leaked from current vrf to vpn\n"
	   "Sid allocation index\n"
	   "Automatically assign a label\n"
	   "Explicitly assign a sid value\n"
	   "Sid value\n")
{
	char buf[16];

	if (no) {
		bgp_cli_sid_vpn_per_vrf_clear(vty);
		return nb_cli_apply_changes(vty, NULL);
	}

	if (!sid_idx_str && !sid_auto && !sid_explicit)
		return CMD_WARNING_CONFIG_FAILED;

	if (!sid_auto)
		nb_cli_enqueue_change(vty, "./global/sid-vpn-per-vrf-export/sid-auto",
				      NB_OP_DESTROY, NULL);
	if (!sid_explicit)
		nb_cli_enqueue_change(vty, "./global/sid-vpn-per-vrf-export/sid-explicit",
				      NB_OP_DESTROY, NULL);
	if (!sid_idx_str)
		nb_cli_enqueue_change(vty, "./global/sid-vpn-per-vrf-export/sid-index",
				      NB_OP_DESTROY, NULL);

	if (sid_auto)
		nb_cli_enqueue_change(vty, "./global/sid-vpn-per-vrf-export/sid-auto",
				      NB_OP_CREATE, NULL);
	else if (sid_explicit)
		nb_cli_enqueue_change(vty, "./global/sid-vpn-per-vrf-export/sid-explicit",
				      NB_OP_MODIFY, sid_value_str);
	else {
		snprintfrr(buf, sizeof(buf), "%" PRId64, sid_idx);
		nb_cli_enqueue_change(vty, "./global/sid-vpn-per-vrf-export/sid-index",
				      NB_OP_MODIFY, buf);
	}

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_ls_distribute_bgp_fabric_yang,
	   bgp_ls_distribute_bgp_fabric_yang_cmd,
	   "[no] distribute bgp-fabric-link-state [instance-id WORD$instance_id_str]",
	   NO_STR
	   "Distribute BGP link-state topology information\n"
	   "Enable BGP fabric link-state topology distribution\n"
	   "BGP-LS instance identifier\n"
	   "Instance ID value\n")
{
	char af_xpath[XPATH_MAXLEN];
	char cont[XPATH_MAXLEN + 256];
	char leaf[XPATH_MAXLEN + 512];
	char *endp = NULL;
	uint64_t instance_id = 0;

	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);
	snprintfrr(cont, sizeof(cont), "%s/distribute/bgp-fabric-link-state", af_xpath);

	if (no) {
		nb_cli_enqueue_change(vty, cont, NB_OP_DESTROY, NULL);
		return nb_cli_apply_changes(vty, NULL);
	}

	if (instance_id_str) {
		errno = 0;
		instance_id = strtoull(instance_id_str, &endp, 10);
		if (errno == ERANGE || endp == instance_id_str || *endp != '\0') {
			vty_out(vty, "%% Invalid instance-id\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	nb_cli_enqueue_change(vty, cont, NB_OP_CREATE, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/instance-id", cont);
	{
		char buf[32];

		snprintfrr(buf, sizeof(buf), "%" PRIu64, instance_id);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, buf);
	}
	return nb_cli_apply_changes(vty, NULL);
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
	int pending_err = vty->pending_commit_error;
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
	if (ret == CMD_SUCCESS && bgp && !vty->pending_commit &&
	    vty->pending_commit_error == pending_err)
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
	int ret;
	char asplain[32];
	struct bgp *bgp;

	if (!asn_str2asn(argv[3]->arg, &as)) {
		vty_out(vty, "%% Invalid AS number: %s\n", argv[3]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}
	/*
	 * Do not VTY_DECLVAR_CONTEXT here: during integrated frr.conf load
	 * (XFRR batch) router-bgp context is not pushed until commit, and
	 * DECLVAR would abort before YANG apply — leaving confed_id unset.
	 */
	snprintfrr(asplain, sizeof(asplain), "%u", as);
	nb_cli_enqueue_change(vty, "./global/confederation/identifier", NB_OP_MODIFY, asplain);
	ret = nb_cli_apply_changes(vty, NULL);
	/*
	 * Preserve user-facing notation (e.g. "1.0") when the instance
	 * already exists (interactive / post-commit). During XFRR batch
	 * bgp is often still NULL — the NB modify callback sets confed_id.
	 */
	if (ret == CMD_SUCCESS) {
		bgp = VTY_GET_CONTEXT(bgp);
		if (bgp)
			bgp_confederation_id_set(bgp, as, argv[3]->arg);
	}
	return ret;
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
	as_t as;

	for (i = 3; i < argc; i++) {
		if (!asn_str2asn(argv[i]->arg, &as)) {
			vty_out(vty, "%% Invalid AS number: %s\n", argv[i]->arg);
			return CMD_WARNING_CONFIG_FAILED;
		}
		snprintfrr(xpath, sizeof(xpath), "./global/confederation/member-as[.='%s']",
			   asn_asn2asplain(as));
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
	as_t as;

	for (i = 4; i < argc; i++) {
		if (!asn_str2asn(argv[i]->arg, &as)) {
			vty_out(vty, "%% Invalid AS number: %s\n", argv[i]->arg);
			return CMD_WARNING_CONFIG_FAILED;
		}
		snprintfrr(xpath, sizeof(xpath), "./global/confederation/member-as[.='%s']",
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

DEFPY_YANG(bgp_rmap_delay_timer_yang, bgp_rmap_delay_timer_yang_cmd,
	   "[no] bgp route-map delay-timer [(0-600)$timer]",
	   NO_STR BGP_STR
	   "BGP route-map delay timer\n"
	   "Time in secs to wait before processing route-map changes\n"
	   "0 disables the timer, no route updates happen when route-maps change\n")
{
	char buf[16];

	if (no) {
		nb_cli_enqueue_change(vty, "./global/global-config-timers/rmap-delay-time",
				      NB_OP_DESTROY, NULL);
		return nb_cli_apply_changes(vty, NULL);
	}

	if (!timer_str) {
		vty_out(vty, "%% Incomplete command\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	snprintfrr(buf, sizeof(buf), "%" PRId64, timer);
	nb_cli_enqueue_change(vty, "./global/global-config-timers/rmap-delay-time", NB_OP_MODIFY,
			      buf);
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

/* Daemon-wide (CONFIG_NODE) /frr-bgp:bgp-daemon knobs */

DEFUN_YANG(bgp_daemon_norib_yang, bgp_daemon_norib_yang_cmd,
	   "bgp no-rib",
	   BGP_STR
	   "Disable BGP route installation to RIB (Zebra)\n")
{
	nb_cli_enqueue_change(vty, "/frr-bgp:bgp-daemon/no-rib", NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_daemon_norib_yang, no_bgp_daemon_norib_yang_cmd,
	   "no bgp no-rib",
	   NO_STR BGP_STR
	   "Disable BGP route installation to RIB (Zebra)\n")
{
	nb_cli_enqueue_change(vty, "/frr-bgp:bgp-daemon/no-rib", NB_OP_MODIFY, "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_daemon_session_dscp_yang, bgp_daemon_session_dscp_yang_cmd,
	   "bgp session-dscp (0-63)$dscp",
	   BGP_STR
	   "Override default (CS6) DSCP for BGP connections\n"
	   "Manually configured DSCP value\n")
{
	char buf[8];

	snprintfrr(buf, sizeof(buf), "%" PRId64, dscp);
	nb_cli_enqueue_change(vty, "/frr-bgp:bgp-daemon/session-dscp", NB_OP_MODIFY, buf);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_daemon_session_dscp_yang, no_bgp_daemon_session_dscp_yang_cmd,
	   "no bgp session-dscp [(0-63)]",
	   NO_STR BGP_STR
	   "Override default (CS6) DSCP for BGP connections\n"
	   "Manually configured DSCP value\n")
{
	nb_cli_enqueue_change(vty, "/frr-bgp:bgp-daemon/session-dscp", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_daemon_inq_limit_yang, bgp_daemon_inq_limit_yang_cmd,
	   "bgp input-queue-limit (1-4294967295)$limit",
	   BGP_STR
	   "Set the BGP Input Queue limit for all peers when message parsing\n"
	   "Input-Queue limit\n")
{
	char buf[16];

	snprintfrr(buf, sizeof(buf), "%" PRId64, limit);
	nb_cli_enqueue_change(vty, "/frr-bgp:bgp-daemon/input-queue-limit", NB_OP_MODIFY, buf);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_daemon_inq_limit_yang, no_bgp_daemon_inq_limit_yang_cmd,
	   "no bgp input-queue-limit [(1-4294967295)]",
	   NO_STR BGP_STR
	   "Set the BGP Input Queue limit for all peers when message parsing\n"
	   "Input-Queue limit\n")
{
	nb_cli_enqueue_change(vty, "/frr-bgp:bgp-daemon/input-queue-limit", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_daemon_outq_limit_yang, bgp_daemon_outq_limit_yang_cmd,
	   "bgp output-queue-limit (1-4294967295)$limit",
	   BGP_STR
	   "Set the BGP Output Queue limit for all peers when message parsing\n"
	   "Output-Queue limit\n")
{
	char buf[16];

	snprintfrr(buf, sizeof(buf), "%" PRId64, limit);
	nb_cli_enqueue_change(vty, "/frr-bgp:bgp-daemon/output-queue-limit", NB_OP_MODIFY, buf);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_daemon_outq_limit_yang, no_bgp_daemon_outq_limit_yang_cmd,
	   "no bgp output-queue-limit [(1-4294967295)]",
	   NO_STR BGP_STR
	   "Set the BGP Output Queue limit for all peers when message parsing\n"
	   "Output-Queue limit\n")
{
	nb_cli_enqueue_change(vty, "/frr-bgp:bgp-daemon/output-queue-limit", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_daemon_suppress_fib_yang, bgp_daemon_suppress_fib_yang_cmd,
	   "[no] bgp suppress-fib-pending [(0-10000)$delay]",
	   NO_STR BGP_STR
	   "Advertise only routes that are programmed in kernel to peers globally\n"
	   "Advertisement delay in milliseconds after FIB installation (default 1000)\n")
{
	char val[16];
	int64_t adv_delay = delay_str ? delay : BGP_DEFAULT_SUPPRESS_FIB_ADV_DELAY;

	if (no) {
		nb_cli_enqueue_change(vty, "/frr-bgp:bgp-daemon/suppress-fib-pending-delay",
				      NB_OP_DESTROY, NULL);
		nb_cli_enqueue_change(vty, "/frr-bgp:bgp-daemon/suppress-fib-pending",
				      NB_OP_MODIFY, "false");
	} else {
		snprintfrr(val, sizeof(val), "%" PRId64, adv_delay);
		nb_cli_enqueue_change(vty, "/frr-bgp:bgp-daemon/suppress-fib-pending",
				      NB_OP_MODIFY, "true");
		nb_cli_enqueue_change(vty, "/frr-bgp:bgp-daemon/suppress-fib-pending-delay",
				      NB_OP_MODIFY, val);
	}
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_daemon_update_delay_yang, bgp_daemon_update_delay_yang_cmd,
	   "bgp update-delay (0-3600)$delay [(1-3600)$wait]",
	   BGP_STR
	   "Force initial delay for best-path and updates for all bgp instances\n"
	   "Max delay in seconds\n"
	   "Establish wait in seconds\n")
{
	char wstr[16];

	nb_cli_enqueue_change(vty, "/frr-bgp:bgp-daemon/update-delay-time", NB_OP_MODIFY,
			      delay_str);
	snprintfrr(wstr, sizeof(wstr), "%" PRId64, wait ? wait : delay);
	nb_cli_enqueue_change(vty, "/frr-bgp:bgp-daemon/establish-wait-time", NB_OP_MODIFY, wstr);

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_daemon_update_delay_yang, no_bgp_daemon_update_delay_yang_cmd,
	   "no bgp update-delay [(0-3600) [(1-3600)]]",
	   NO_STR BGP_STR
	   "Force initial delay for best-path and updates\n"
	   "Max delay in seconds\n"
	   "Establish wait in seconds\n")
{
	nb_cli_enqueue_change(vty, "/frr-bgp:bgp-daemon/update-delay-time", NB_OP_DESTROY, NULL);
	nb_cli_enqueue_change(vty, "/frr-bgp:bgp-daemon/establish-wait-time", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_daemon_advertisement_delay_yang,
	   bgp_daemon_advertisement_delay_yang_cmd,
	   "bgp advertisement-delay (1-3600)$delay",
	   BGP_STR
	   "Hold route advertisements to peers for configured seconds after first peer establishes\n"
	   "Delay in seconds\n")
{
	nb_cli_enqueue_change(vty, "/frr-bgp:bgp-daemon/advertisement-delay-time", NB_OP_MODIFY,
			      delay_str);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_daemon_advertisement_delay_yang,
	   no_bgp_daemon_advertisement_delay_yang_cmd,
	   "no bgp advertisement-delay [(1-3600)]",
	   NO_STR BGP_STR
	   "Hold route advertisements to peers for configured seconds after first peer establishes\n"
	   "Delay in seconds\n")
{
	nb_cli_enqueue_change(vty, "/frr-bgp:bgp-daemon/advertisement-delay-time", NB_OP_DESTROY,
			      NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_daemon_community_alias_yang,
	   bgp_daemon_community_alias_yang_cmd,
	   "[no$no] bgp community alias WORD$community ALIAS_NAME$alias_name",
	   NO_STR BGP_STR
	   "Add community specific parameters\n"
	   "Create an alias for a community\n"
	   "Community (AA:BB or AA:BB:CC)\n"
	   "Alias name\n")
{
	char xpath[XPATH_MAXLEN];

	snprintfrr(xpath, sizeof(xpath), "/frr-bgp:bgp-daemon/community-alias[community='%s']",
		   community);
	if (no) {
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	} else {
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
		nb_cli_enqueue_change(vty, "./alias", NB_OP_MODIFY, alias_name);
	}
	return nb_cli_apply_changes(vty, "%s", xpath);
}

DEFPY_YANG(bgp_daemon_send_extra_data_yang,
	   bgp_daemon_send_extra_data_yang_cmd,
	   "[no] bgp send-extra-data zebra",
	   NO_STR BGP_STR
	   "Extra data to Zebra for display/use\n"
	   "To zebra\n")
{
	nb_cli_enqueue_change(vty, "/frr-bgp:bgp-daemon/send-extra-data", NB_OP_MODIFY,
			      no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_daemon_snmp_traps_rfc4273_yang,
	   bgp_daemon_snmp_traps_rfc4273_yang_cmd,
	   "[no] bgp snmp traps rfc4273",
	   NO_STR BGP_STR
	   "Configure BGP SNMP\n"
	   "Configure SNMP traps for BGP\n"
	   "Configure use of rfc4273 SNMP traps for BGP\n")
{
	nb_cli_enqueue_change(vty, "/frr-bgp:bgp-daemon/snmp-traps/rfc4273", NB_OP_MODIFY,
			      no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_daemon_snmp_traps_bgp4_mibv2_yang,
	   bgp_daemon_snmp_traps_bgp4_mibv2_yang_cmd,
	   "[no] bgp snmp traps bgp4-mibv2",
	   NO_STR BGP_STR
	   "Configure BGP SNMP\n"
	   "Configure SNMP traps for BGP\n"
	   "Configure use of BGP4-MIBv2 SNMP traps for BGP\n")
{
	nb_cli_enqueue_change(vty, "/frr-bgp:bgp-daemon/snmp-traps/bgp4-mibv2", NB_OP_MODIFY,
			      no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_daemon_snmp_traps_rfc4382_yang,
	   bgp_daemon_snmp_traps_rfc4382_yang_cmd,
	   "[no] bgp snmp traps rfc4382",
	   NO_STR BGP_STR
	   "Configure BGP SNMP\n"
	   "Configure SNMP traps for BGP\n"
	   "Configure use of rfc4382 SNMP traps for BGP\n")
{
	nb_cli_enqueue_change(vty, "/frr-bgp:bgp-daemon/snmp-traps/rfc4382", NB_OP_MODIFY,
			      no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_daemon_rmap_delay_timer_yang,
	   bgp_daemon_rmap_delay_timer_yang_cmd,
	   "[no] bgp route-map delay-timer [(0-600)$timer]",
	   NO_STR BGP_STR
	   "BGP route-map delay timer\n"
	   "Time in secs to wait before processing route-map changes\n"
	   "0 disables the timer, no route updates happen when route-maps change\n")
{
	char buf[16];

	if (no) {
		nb_cli_enqueue_change(vty, "/frr-bgp:bgp-daemon/rmap-delay-time", NB_OP_DESTROY,
				      NULL);
		return nb_cli_apply_changes(vty, NULL);
	}

	if (!timer_str) {
		vty_out(vty, "%% Incomplete command\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	snprintfrr(buf, sizeof(buf), "%" PRId64, timer);
	nb_cli_enqueue_change(vty, "/frr-bgp:bgp-daemon/rmap-delay-time", NB_OP_MODIFY, buf);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(bgp_daemon_graceful_restart_yang,
	   bgp_daemon_graceful_restart_yang_cmd,
	   "bgp graceful-restart", BGP_STR GR_CMD)
{
	nb_cli_enqueue_change(vty, "/frr-bgp:bgp-daemon/graceful-restart/graceful-restart-disable",
			      NB_OP_DESTROY, NULL);
	nb_cli_enqueue_change(vty, "/frr-bgp:bgp-daemon/graceful-restart/enabled", NB_OP_MODIFY,
			      "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_daemon_graceful_restart_yang,
	   no_bgp_daemon_graceful_restart_yang_cmd,
	   "no bgp graceful-restart", NO_STR BGP_STR NO_GR_CMD)
{
	nb_cli_enqueue_change(vty, "/frr-bgp:bgp-daemon/graceful-restart/enabled", NB_OP_DESTROY,
			      NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(bgp_daemon_graceful_restart_disable_yang,
	   bgp_daemon_graceful_restart_disable_yang_cmd,
	   "bgp graceful-restart-disable", BGP_STR GR_DISABLE)
{
	nb_cli_enqueue_change(vty, "/frr-bgp:bgp-daemon/graceful-restart/enabled", NB_OP_DESTROY,
			      NULL);
	nb_cli_enqueue_change(vty, "/frr-bgp:bgp-daemon/graceful-restart/graceful-restart-disable",
			      NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_daemon_graceful_restart_disable_yang,
	   no_bgp_daemon_graceful_restart_disable_yang_cmd,
	   "no bgp graceful-restart-disable", NO_STR BGP_STR NO_GR_DISABLE)
{
	nb_cli_enqueue_change(vty, "/frr-bgp:bgp-daemon/graceful-restart/graceful-restart-disable",
			      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(bgp_daemon_gr_stalepath_time_yang,
	   bgp_daemon_gr_stalepath_time_yang_cmd,
	   "bgp graceful-restart stalepath-time (1-4095)",
	   BGP_STR
	   "Graceful restart capability parameters\n"
	   "Set the max time to hold onto restarting peer's stale paths\n"
	   "Delay value (seconds)\n")
{
	nb_cli_enqueue_change(vty, "/frr-bgp:bgp-daemon/graceful-restart/stale-routes-time",
			      NB_OP_MODIFY, argv[3]->arg);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_daemon_gr_stalepath_time_yang,
	   no_bgp_daemon_gr_stalepath_time_yang_cmd,
	   "no bgp graceful-restart stalepath-time [(1-4095)]",
	   NO_STR BGP_STR
	   "Graceful restart capability parameters\n"
	   "Set the max time to hold onto restarting peer's stale paths\n"
	   "Delay value (seconds)\n")
{
	char val[16];

	snprintfrr(val, sizeof(val), "%u", BGP_DEFAULT_STALEPATH_TIME);
	nb_cli_enqueue_change(vty, "/frr-bgp:bgp-daemon/graceful-restart/stale-routes-time",
			      NB_OP_MODIFY, val);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(bgp_daemon_gr_restart_time_yang,
	   bgp_daemon_gr_restart_time_yang_cmd,
	   "bgp graceful-restart restart-time (0-4095)",
	   BGP_STR
	   "Graceful restart capability parameters\n"
	   "Set the time to wait to delete stale routes before a BGP open message is received\n"
	   "Delay value (seconds)\n")
{
	nb_cli_enqueue_change(vty, "/frr-bgp:bgp-daemon/graceful-restart/restart-time",
			      NB_OP_MODIFY, argv[3]->arg);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_daemon_gr_restart_time_yang,
	   no_bgp_daemon_gr_restart_time_yang_cmd,
	   "no bgp graceful-restart restart-time [(0-4095)]",
	   NO_STR BGP_STR
	   "Graceful restart capability parameters\n"
	   "Set the time to wait to delete stale routes before a BGP open message is received\n"
	   "Delay value (seconds)\n")
{
	char val[16];

	snprintfrr(val, sizeof(val), "%u", BGP_DEFAULT_RESTART_TIME);
	nb_cli_enqueue_change(vty, "/frr-bgp:bgp-daemon/graceful-restart/restart-time",
			      NB_OP_MODIFY, val);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(bgp_daemon_gr_select_defer_time_yang,
	   bgp_daemon_gr_select_defer_time_yang_cmd,
	   "bgp graceful-restart select-defer-time (0-3600)",
	   BGP_STR
	   "Graceful restart capability parameters\n"
	   "Set the time to defer the BGP route selection after restart\n"
	   "Delay value (seconds, 0 - disable)\n")
{
	nb_cli_enqueue_change(vty, "/frr-bgp:bgp-daemon/graceful-restart/selection-deferral-time",
			      NB_OP_MODIFY, argv[3]->arg);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_daemon_gr_select_defer_time_yang,
	   no_bgp_daemon_gr_select_defer_time_yang_cmd,
	   "no bgp graceful-restart select-defer-time [(0-3600)]",
	   NO_STR BGP_STR
	   "Graceful restart capability parameters\n"
	   "Set the time to defer the BGP route selection after restart\n"
	   "Delay value (seconds, 0 - disable)\n")
{
	char val[16];

	snprintfrr(val, sizeof(val), "%u", BGP_DEFAULT_SELECT_DEFERRAL_TIME);
	nb_cli_enqueue_change(vty, "/frr-bgp:bgp-daemon/graceful-restart/selection-deferral-time",
			      NB_OP_MODIFY, val);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(bgp_daemon_gr_rib_stale_time_yang,
	   bgp_daemon_gr_rib_stale_time_yang_cmd,
	   "bgp graceful-restart rib-stale-time (1-3600)",
	   BGP_STR
	   "Graceful restart configuration parameters\n"
	   "Specify the stale route removal timer in rib\n"
	   "Delay value (seconds)\n")
{
	nb_cli_enqueue_change(vty, "/frr-bgp:bgp-daemon/graceful-restart/rib-stale-time",
			      NB_OP_MODIFY, argv[3]->arg);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_daemon_gr_rib_stale_time_yang,
	   no_bgp_daemon_gr_rib_stale_time_yang_cmd,
	   "no bgp graceful-restart rib-stale-time [(1-3600)]",
	   NO_STR BGP_STR
	   "Graceful restart configuration parameters\n"
	   "Specify the stale route removal timer in rib\n"
	   "Delay value (seconds)\n")
{
	char val[16];

	snprintfrr(val, sizeof(val), "%u", BGP_DEFAULT_RIB_STALE_TIME);
	nb_cli_enqueue_change(vty, "/frr-bgp:bgp-daemon/graceful-restart/rib-stale-time",
			      NB_OP_MODIFY, val);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(bgp_daemon_gr_preserve_fw_yang,
	   bgp_daemon_gr_preserve_fw_yang_cmd,
	   "bgp graceful-restart preserve-fw-state",
	   BGP_STR
	   "Graceful restart capability parameters\n"
	   "Sets F-bit indication that fib is preserved while doing Graceful Restart\n")
{
	nb_cli_enqueue_change(vty, "/frr-bgp:bgp-daemon/graceful-restart/preserve-fw-entry",
			      NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_daemon_gr_preserve_fw_yang,
	   no_bgp_daemon_gr_preserve_fw_yang_cmd,
	   "no bgp graceful-restart preserve-fw-state",
	   NO_STR BGP_STR
	   "Graceful restart capability parameters\n"
	   "Unsets F-bit indication that fib is preserved while doing Graceful Restart\n")
{
	nb_cli_enqueue_change(vty, "/frr-bgp:bgp-daemon/graceful-restart/preserve-fw-entry",
			      NB_OP_MODIFY, "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(bgp_daemon_graceful_shutdown_yang,
	   bgp_daemon_graceful_shutdown_yang_cmd,
	   "bgp graceful-shutdown", BGP_STR "Graceful shutdown parameters\n")
{
	nb_cli_enqueue_change(vty, "/frr-bgp:bgp-daemon/graceful-shutdown/enable", NB_OP_MODIFY,
			      "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_bgp_daemon_graceful_shutdown_yang,
	   no_bgp_daemon_graceful_shutdown_yang_cmd,
	   "no bgp graceful-shutdown",
	   NO_STR BGP_STR "Graceful shutdown parameters\n")
{
	nb_cli_enqueue_change(vty, "/frr-bgp:bgp-daemon/graceful-shutdown/enable", NB_OP_MODIFY,
			      "false");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_condadv_period_yang, bgp_condadv_period_yang_cmd,
	   "[no$no] bgp conditional-advertisement timer (5-240)$period",
	   NO_STR BGP_STR
	   "Conditional advertisement settings\n"
	   "Set period to rescan BGP table to check if condition is met\n"
	   "Period between BGP table scans, in seconds; default 60\n")
{
	if (no)
		nb_cli_enqueue_change(vty,
				      "./global/global-config-timers/conditional-advertisement-timer",
				      NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty,
				      "./global/global-config-timers/conditional-advertisement-timer",
				      NB_OP_MODIFY, period_str);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_def_originate_eval_yang, bgp_def_originate_eval_yang_cmd,
	   "[no$no] bgp default-originate timer (0-65535)$timer",
	   NO_STR BGP_STR
	   "Control default-originate\n"
	   "Set period to rescan BGP table to check if default-originate condition is met\n"
	   "Period between BGP table scans, in seconds; default 5\n")
{
	if (no)
		nb_cli_enqueue_change(vty, "./global/global-config-timers/default-originate-timer",
				      NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, "./global/global-config-timers/default-originate-timer",
				      NB_OP_MODIFY, timer_str);
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

DEFPY_YANG(bgp_listen_range_yang, bgp_listen_range_yang_cmd,
	   "[no] bgp listen range <A.B.C.D/M|X:X::X:X/M>$prefix peer-group WORD$pg",
	   NO_STR BGP_STR
	   "Configure BGP dynamic neighbors listen range\n"
	   "Configure BGP dynamic neighbors listen range\n"
	   NEIGHBOR_ADDR_STR
	   "Member of the peer-group\n"
	   "Peer-group name\n")
{
	struct prefix range;
	char pfx[PREFIX_STRLEN];
	char xpath[XPATH_MAXLEN];
	char check[XPATH_MAXLEN + 256];
	const char *leaf;
	struct bgp *bgp;
	struct peer_group *group;
	int ret;

	if (prefix->family == AF_INET6 && IN6_IS_ADDR_LINKLOCAL(&prefix->u.prefix6)) {
		vty_out(vty, "%% Malformed listen range (link-local address)\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	range = *prefix;
	apply_mask(&range);

	/*
	 * During XFRR_start_configuration batching, peer-groups exist only in
	 * the candidate. Runtime peer_group_lookup() fails mid-file and would
	 * drop listen-ranges (breaking dynamic MD5 peers). Match password CLI.
	 */
	snprintfrr(check, sizeof(check), "%s/peer-groups/peer-group[peer-group-name='%s']",
		   VTY_CURR_XPATH, pg);
	if (!yang_dnode_exists(vty->candidate_config->dnode, check)) {
		vty_out(vty, no ? "%% Peer-group does not exist\n"
				: "%% Configure the peer-group first\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Overlap / duplicate checks run in NB VALIDATE on commit. */

	leaf = (range.family == AF_INET) ? "ipv4-listen-range" : "ipv6-listen-range";
	snprintfrr(pfx, sizeof(pfx), "%pFX", &range);
	snprintfrr(xpath, sizeof(xpath),
		   "./peer-groups/peer-group[peer-group-name='%s']/%s[.='%s']", pg, leaf, pfx);
	nb_cli_enqueue_change(vty, xpath, no ? NB_OP_DESTROY : NB_OP_CREATE, no ? NULL : pfx);
	ret = nb_cli_apply_changes(vty, NULL);

	/*
	 * Warn about an open (0.0.0.0/0 or ::/0) listen range without a
	 * password (db1ca25485). Skip it while frr.conf is loading: the
	 * password may be configured later in the file. When the change is
	 * batched and not yet applied, the range is not in the runtime group
	 * and nothing is printed.
	 */
	if (ret == CMD_SUCCESS && !no && !bgp_config_inprocess() &&
	    (bgp = VTY_GET_CONTEXT(bgp)) != NULL && (group = peer_group_lookup(bgp, pg)) != NULL) {
		struct listnode *node;
		struct prefix *lr;

		for (ALL_LIST_ELEMENTS_RO(group->listen_range[range.family == AF_INET ? AFI_IP
										      : AFI_IP6],
					  node, lr))
			if (prefix_same(lr, &range))
				bgp_listen_range_warn(vty, group, lr);
	}

	return ret;
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

DEFPY_YANG(bgp_default_originate_setonly_yang, bgp_default_originate_setonly_yang_cmd,
	   "[no] bgp default-originate set-only-unconditional",
	   NO_STR BGP_STR
	   "Control default-originate behavior\n"
	   "Permit set-only route-maps to originate default even with empty table\n")
{
	nb_cli_enqueue_change(vty, "./global/default-originate-set-only-unconditional",
			      NB_OP_MODIFY, no ? "false" : "true");
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
	int ret;

	msgstr = argv_concat(argv, argc, 3);
	nb_cli_enqueue_change(vty, "./global/shutdown-no-notify", NB_OP_DESTROY, NULL);
	nb_cli_enqueue_change(vty, "./global/shutdown", NB_OP_MODIFY, "true");
	nb_cli_enqueue_change(vty, "./global/shutdown-message", NB_OP_MODIFY, msgstr);
	/* Pointer is stored in the change list — free only after apply. */
	ret = nb_cli_apply_changes(vty, NULL);
	XFREE(MTYPE_TMP, msgstr);
	return ret;
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
	if (vty->node == CONFIG_NODE) {
		nb_cli_enqueue_change(vty, "/frr-bgp:bgp-daemon/ipv6-auto-ra", NB_OP_MODIFY,
				      no ? "false" : "true");
		return nb_cli_apply_changes(vty, NULL);
	}

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
	const char *val = value;

	if (no) {
		VTY_DECLVAR_CONTEXT(bgp, bgp);
		uint64_t remain = bgp->flags & (BGP_FLAG_LU_IPV4_EXPLICIT_NULL |
						BGP_FLAG_LU_IPV6_EXPLICIT_NULL);

		if (strmatch(value, "ipv4-explicit-null"))
			remain &= ~BGP_FLAG_LU_IPV4_EXPLICIT_NULL;
		else if (strmatch(value, "ipv6-explicit-null"))
			remain &= ~BGP_FLAG_LU_IPV6_EXPLICIT_NULL;
		else
			remain = 0;

		if (CHECK_FLAG(remain, BGP_FLAG_LU_IPV4_EXPLICIT_NULL) &&
		    CHECK_FLAG(remain, BGP_FLAG_LU_IPV6_EXPLICIT_NULL))
			val = "explicit-null";
		else if (CHECK_FLAG(remain, BGP_FLAG_LU_IPV4_EXPLICIT_NULL))
			val = "ipv4-explicit-null";
		else if (CHECK_FLAG(remain, BGP_FLAG_LU_IPV6_EXPLICIT_NULL))
			val = "ipv6-explicit-null";
		else
			val = "none";
	}

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
 * Returns 0 on success. For WORD, prefers an existing unnumbered neighbor
 * in the candidate, otherwise peer-group (which must already exist for
 * remote-as — matching classic "create the peer-group first").
 */
static int bgp_cli_neighbor_base_xpath(struct vty *vty, const char *neighbor, char *xpath,
				       size_t xpath_len, bool *is_peer_group)
{
	char check[XPATH_MAXLEN + 256];
	union sockunion su;

	*is_peer_group = false;

	if (str2sockunion(neighbor, &su) >= 0) {
		snprintfrr(xpath, xpath_len, "./neighbors/neighbor[remote-address='%s']", neighbor);
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
	} else {
		/*
		 * remote-as is when-gated on as-specified. Clear any leftover
		 * ASN leaf before switching to internal/external/auto.
		 */
		snprintfrr(leaf, sizeof(leaf), "%s/neighbor-remote-as/remote-as", base_xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);

		if (internal)
			as_type = "internal";
		else if (as_auto)
			as_type = "auto";
		else
			as_type = "external";
		snprintfrr(leaf, sizeof(leaf), "%s/neighbor-remote-as/remote-as-type", base_xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, as_type);
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
	uint32_t nlisten;

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

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
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
	ret = nb_cli_apply_changes(vty, NULL);
	XFREE(MTYPE_TMP, str);
	return ret;
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

DEFPY_YANG(neighbor_ls_local_link_id_yang, neighbor_ls_local_link_id_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$peer_str local-link-id [(1-4294967295)$link_id]",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Configure local link ID for BGP-LS topology\n"
	   "Link identifier value\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	char buf[16];
	bool is_pg = false;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, peer_str, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	snprintfrr(leaf, sizeof(leaf), "%s/local-link-id", xpath);
	if (no)
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	else {
		if (!link_id_str) {
			vty_out(vty, "%% Incomplete command\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		snprintfrr(buf, sizeof(buf), "%" PRId64, link_id);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, buf);
	}
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_ls_remote_link_id_yang, neighbor_ls_remote_link_id_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$peer_str remote-link-id [(1-4294967295)$link_id]",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Configure remote link ID for BGP-LS topology\n"
	   "Link identifier value\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	char buf[16];
	bool is_pg = false;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, peer_str, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	snprintfrr(leaf, sizeof(leaf), "%s/remote-link-id", xpath);
	if (no)
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	else {
		if (!link_id_str) {
			vty_out(vty, "%% Incomplete command\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		snprintfrr(buf, sizeof(buf), "%" PRId64, link_id);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, buf);
	}
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
	/* Pointer is stored in the change list — free only after apply. */
	ret = nb_cli_apply_changes(vty, NULL);
	XFREE(MTYPE_TMP, msgstr);
	return ret;
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

DEFPY_YANG(neighbor_shutdown_rtt_yang, neighbor_shutdown_rtt_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor shutdown rtt [(1-65535)$rtt [count (1-255)$count]]",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Administratively shut down this neighbor\n"
	   "Shutdown if round-trip-time is higher than expected\n"
	   "Round-trip-time in milliseconds\n"
	   "Specify the number of keepalives before shutdown\n"
	   "The number of keepalives with higher RTT to shutdown\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	char rtt_buf[16], count_buf[16];
	bool is_pg = false;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	snprintfrr(leaf, sizeof(leaf), "%s/admin-shutdown/rtt", xpath);
	if (no) {
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
		snprintfrr(leaf, sizeof(leaf), "%s/admin-shutdown/rtt-count", xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
		return nb_cli_apply_changes(vty, NULL);
	}

	if (!rtt_str) {
		vty_out(vty, "%% Incomplete command\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	snprintfrr(rtt_buf, sizeof(rtt_buf), "%" PRId64, rtt);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, rtt_buf);
	snprintfrr(leaf, sizeof(leaf), "%s/admin-shutdown/rtt-count", xpath);
	if (count_str) {
		snprintfrr(count_buf, sizeof(count_buf), "%" PRId64, count);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, count_buf);
	} else
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);

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

	/* Clippy parses ASNUM into as_t as_str; YANG leaf is inet:as-number
	 * (uint32). Pass plain ASN, not the original ASDOT string.
	 */
	snprintfrr(leaf, sizeof(leaf), "%s/local-as/local-as", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, asn_asn2asplain(as_str));
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

	/*
	 * "no" stores "disabled". Absent means inherit bgp default
	 * software-version-capability, so deleting the leaf turns the
	 * capability back on when that default is set. "disabled" is the
	 * explicit per-neighbor override.
	 * Capability messages are sent solely by the NB modify callback.
	 */
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
	/* Distinct buffers: nb_cli_enqueue_change stores the pointer, not a copy. */
	char detect_buf[16];
	char min_rx_buf[16];
	char min_tx_buf[16];
	bool is_pg = false;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	snprintfrr(leaf, sizeof(leaf), "%s/bfd-options/enable", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, "true");
	snprintfrr(detect_buf, sizeof(detect_buf), "%" PRId64, detect);
	snprintfrr(leaf, sizeof(leaf), "%s/bfd-options/detect-multiplier", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, detect_buf);
	snprintfrr(min_rx_buf, sizeof(min_rx_buf), "%" PRId64, min_rx);
	snprintfrr(leaf, sizeof(leaf), "%s/bfd-options/required-min-rx", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, min_rx_buf);
	snprintfrr(min_tx_buf, sizeof(min_tx_buf), "%" PRId64, min_tx);
	snprintfrr(leaf, sizeof(leaf), "%s/bfd-options/desired-min-tx", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, min_tx_buf);
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
	const struct lyd_node *nbr = NULL;
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

	if (set && base[0] == '.') {
		/*
		 * The classic command warned about an attribute that cannot be
		 * discarded, skipped it and applied the rest. Do the same here
		 * so a config file that names one still loads. The NB validate
		 * callback rejects it for clients that do not come through
		 * this command.
		 */
		snprintfrr(leaf, sizeof(leaf), "%s%s", VTY_CURR_XPATH, base + 1);
		nbr = yang_dnode_get(vty->candidate_config->dnode, leaf);
	}

	frrstr_split(attrs, " ", &attributes, &num_attributes);
	for (i = 0; i < num_attributes; i++) {
		if (nbr) {
			char why[128];

			if (bgp_nb_path_attr_forbidden(nbr, strtoul(attributes[i], NULL, 10),
						       strmatch(leaf_name, "treat-as-withdraw"),
						       why, sizeof(why))) {
				vty_out(vty, "%% %s\n", why);
				continue;
			}
		}
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

static int bgp_cli_peer_bool_leaf(struct vty *vty, const char *neighbor, const char *leaf_name,
				  bool no)
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	snprintfrr(leaf, sizeof(leaf), "%s/%s", xpath, leaf_name);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_extended_link_bw_yang,
	   neighbor_extended_link_bw_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor extended-link-bandwidth",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Send Extended (64-bit) version of encoding for Link-Bandwidth\n")
{
	return bgp_cli_peer_bool_leaf(vty, neighbor, "extended-link-bandwidth", no);
}

DEFPY_YANG(neighbor_disable_link_bw_ieee_yang,
	   neighbor_disable_link_bw_ieee_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor disable-link-bw-encoding-ieee",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Disable IEEE floating-point encoding for extended community bandwidth\n")
{
	return bgp_cli_peer_bool_leaf(vty, neighbor, "disable-link-bw-encoding-ieee", no);
}

DEFPY_YANG(neighbor_extended_opt_params_yang,
	   neighbor_extended_opt_params_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor extended-optional-parameters",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Force the extended optional parameters format for OPEN messages\n")
{
	return bgp_cli_peer_bool_leaf(vty, neighbor, "extended-optional-parameters", no);
}

DEFPY_YANG(neighbor_send_nhc_yang, neighbor_send_nhc_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor send-nexthop-characteristics",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Send BGP Next Hop Dependent Characteristics Attribute\n")
{
	return bgp_cli_peer_bool_leaf(vty, neighbor, "send-nexthop-characteristics", no);
}

DEFPY_YANG(neighbor_as_loop_detection_yang,
	   neighbor_as_loop_detection_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor sender-as-path-loop-detection",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Detect AS loops before sending to neighbor\n")
{
	return bgp_cli_peer_bool_leaf(vty, neighbor, "sender-as-path-loop-detection", no);
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


DEFPY_YANG(neighbor_set_peer_group_yang, neighbor_set_peer_group_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor peer-group PGNAME$pgname",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Member of the peer-group\n"
	   "Peer-group name\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	char pg_path[XPATH_MAXLEN + 256];
	bool is_pg = false;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	if (is_pg) {
		vty_out(vty, "%% Peer-group cannot join a peer-group\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (no) {
		/*
		 * Classic "no neighbor X peer-group PG" deletes the neighbor,
		 * which drops the listen socket when the instance has no peers
		 * left. Destroying only the peer-group leaf leaves the neighbor
		 * and the wildcard listener in place.
		 */
		snprintfrr(pg_path, sizeof(pg_path),
			   "%s/peer-groups/peer-group[peer-group-name='%s']", VTY_CURR_XPATH,
			   pgname);
		if (!yang_dnode_exists(vty->candidate_config->dnode, pg_path)) {
			vty_out(vty, "%% Configure the peer-group first\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
		return nb_cli_apply_changes(vty, NULL);
	}

	/*
	 * Create the neighbor and point it at the group. Do not copy the
	 * group's remote-as onto the member: that freezes the AS into the
	 * member's own config, and a later group remote-as change is lost
	 * on save/restart. peer_group_bind() inherits while the member has
	 * no remote-as of its own.
	 */
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/peer-group", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, pgname);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_port_yang, neighbor_port_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor port [(0-65535)$port]",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Neighbor's BGP port\n"
	   "TCP port number\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	char buf[16];
	bool is_pg = false;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	snprintfrr(leaf, sizeof(leaf), "%s/local-port", xpath);
	if (no)
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	else {
		if (!port_str) {
			vty_out(vty, "%% Incomplete command\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		snprintfrr(buf, sizeof(buf), "%" PRId64, port);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, buf);
	}
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_local_interface_yang, neighbor_local_interface_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X>$neighbor interface WORD$ifname",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR
	   "Interface\n"
	   "Interface name\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor_str, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	snprintfrr(leaf, sizeof(leaf), "%s/local-interface", xpath);
	if (no)
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, ifname);
	return nb_cli_apply_changes(vty, NULL);
}

/*
 * Enter an address-family mode: create the global afi-safi list entry and
 * switch vty->node. Do not push an AF xpath — YANG AF commands resolve
 * relative to the BGP instance xpath using vty->node.
 */
static bool bgp_cli_yang_is_non_default_instance(struct vty *vty)
{
	const struct lyd_node *bgp_dnode, *cpp;
	const char *vrf;

	if (vty->xpath_index == 0)
		return false;

	bgp_dnode = yang_dnode_get(vty->candidate_config->dnode, VTY_CURR_XPATH);
	if (!bgp_dnode)
		return false;

	if (yang_dnode_exists(bgp_dnode, "./global/instance-type-view") &&
	    yang_dnode_get_bool(bgp_dnode, "./global/instance-type-view"))
		return true;

	cpp = yang_dnode_get_parent(bgp_dnode, "control-plane-protocol");
	if (!cpp)
		return false;
	vrf = yang_dnode_get_string(cpp, "vrf");
	return vrf && !strmatch(vrf, VRF_DEFAULT_NAME);
}

static int bgp_cli_af_enter(struct vty *vty, int node, safi_t safi)
{
	char af_xpath[XPATH_MAXLEN];
	int saved_node = vty->node;
	int ret;

	if (bgp_cli_yang_is_non_default_instance(vty) && safi != SAFI_UNICAST &&
	    safi != SAFI_MULTICAST && safi != SAFI_EVPN) {
		vty_out(vty,
			"Only Unicast/Multicast/EVPN SAFIs supported in non-core instances.\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Temporarily set node so bgp_cli_global_af_xpath() resolves correctly. */
	vty->node = node;
	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);
	ret = nb_cli_apply_changes(vty, NULL);
	if (ret != CMD_SUCCESS)
		vty->node = saved_node;
	return ret;
}

DEFPY_YANG_NOSH(address_family_ipv4_yang, address_family_ipv4_yang_cmd,
		"address-family ipv4 [<unicast|multicast|vpn|labeled-unicast|flowspec|unreachability>$safi]",
		"Enter Address Family command mode\n" BGP_AF_STR
			BGP_SAFI_WITH_LABEL_HELP_STR)
{
	int node;
	safi_t s;

	if (!safi || strmatch(safi, "unicast")) {
		node = BGP_IPV4_NODE;
		s = SAFI_UNICAST;
	} else if (strmatch(safi, "multicast")) {
		node = BGP_IPV4M_NODE;
		s = SAFI_MULTICAST;
	} else if (strmatch(safi, "vpn")) {
		node = BGP_VPNV4_NODE;
		s = SAFI_MPLS_VPN;
	} else if (strmatch(safi, "labeled-unicast")) {
		node = BGP_IPV4L_NODE;
		s = SAFI_LABELED_UNICAST;
	} else if (strmatch(safi, "flowspec")) {
		node = BGP_FLOWSPECV4_NODE;
		s = SAFI_FLOWSPEC;
	} else if (strmatch(safi, "unreachability")) {
		node = BGP_IPV4U_NODE;
		s = SAFI_UNREACH;
	} else {
		vty_out(vty, "%% Unknown SAFI %s\n", safi);
		return CMD_WARNING_CONFIG_FAILED;
	}

	return bgp_cli_af_enter(vty, node, s);
}

DEFPY_YANG_NOSH(address_family_ipv6_yang, address_family_ipv6_yang_cmd,
		"address-family ipv6 [<unicast|multicast|vpn|labeled-unicast|flowspec|unreachability>$safi]",
		"Enter Address Family command mode\n" BGP_AF_STR
			BGP_SAFI_WITH_LABEL_HELP_STR)
{
	int node;
	safi_t s;

	if (!safi || strmatch(safi, "unicast")) {
		node = BGP_IPV6_NODE;
		s = SAFI_UNICAST;
	} else if (strmatch(safi, "multicast")) {
		node = BGP_IPV6M_NODE;
		s = SAFI_MULTICAST;
	} else if (strmatch(safi, "vpn")) {
		node = BGP_VPNV6_NODE;
		s = SAFI_MPLS_VPN;
	} else if (strmatch(safi, "labeled-unicast")) {
		node = BGP_IPV6L_NODE;
		s = SAFI_LABELED_UNICAST;
	} else if (strmatch(safi, "flowspec")) {
		node = BGP_FLOWSPECV6_NODE;
		s = SAFI_FLOWSPEC;
	} else if (strmatch(safi, "unreachability")) {
		node = BGP_IPV6U_NODE;
		s = SAFI_UNREACH;
	} else {
		vty_out(vty, "%% Unknown SAFI %s\n", safi);
		return CMD_WARNING_CONFIG_FAILED;
	}

	return bgp_cli_af_enter(vty, node, s);
}

#ifdef KEEP_OLD_VPN_COMMANDS
DEFPY_YANG_NOSH(address_family_vpnv4_yang, address_family_vpnv4_yang_cmd,
		"address-family vpnv4 [unicast]",
		"Enter Address Family command mode\n" BGP_AF_STR
			BGP_AF_MODIFIER_STR)
{
	return bgp_cli_af_enter(vty, BGP_VPNV4_NODE, SAFI_MPLS_VPN);
}

DEFPY_YANG_NOSH(address_family_vpnv6_yang, address_family_vpnv6_yang_cmd,
		"address-family vpnv6 [unicast]",
		"Enter Address Family command mode\n" BGP_AF_STR
			BGP_AF_MODIFIER_STR)
{
	return bgp_cli_af_enter(vty, BGP_VPNV6_NODE, SAFI_MPLS_VPN);
}
#endif /* KEEP_OLD_VPN_COMMANDS */

DEFPY_YANG_NOSH(address_family_evpn_yang, address_family_evpn_yang_cmd,
		"address-family l2vpn evpn",
		"Enter Address Family command mode\n" BGP_AF_STR
			BGP_AF_MODIFIER_STR)
{
	return bgp_cli_af_enter(vty, BGP_EVPN_NODE, SAFI_EVPN);
}

DEFPY_YANG_NOSH(address_family_link_state_yang,
		address_family_link_state_yang_cmd,
		"address-family link-state [link-state]",
		"Enter Address Family command mode\n"
		"Link-State Address Family\n"
		"Link-State Subsequent Address Family\n")
{
	/*
	 * Classic enter did not check instance type; mirror that. Create the
	 * afi-safi entry and switch node only on success.
	 */
	char af_xpath[XPATH_MAXLEN];
	int saved_node = vty->node;
	int ret;

	vty->node = BGP_LS_NODE;
	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);
	ret = nb_cli_apply_changes(vty, NULL);
	if (ret != CMD_SUCCESS)
		vty->node = saved_node;
	return ret;
}

/*
 * Interface MPLS BGP knobs (INTERFACE_NODE; xpath from if_cmd_init).
 */
DEFPY_YANG(mpls_bgp_forwarding_yang, mpls_bgp_forwarding_yang_cmd,
	   "[no$no] mpls bgp forwarding",
	   NO_STR MPLS_STR BGP_STR
	   "Enable MPLS forwarding for eBGP directly connected peers\n")
{
	nb_cli_enqueue_change(vty, "./frr-bgp:mpls-bgp-forwarding", NB_OP_MODIFY,
			      no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(mpls_bgp_l3vpn_multi_domain_switching_yang,
	   mpls_bgp_l3vpn_multi_domain_switching_yang_cmd,
	   "[no$no] mpls bgp l3vpn-multi-domain-switching",
	   NO_STR MPLS_STR BGP_STR
	   "Bind a local MPLS label to incoming L3VPN updates\n")
{
	nb_cli_enqueue_change(vty, "./frr-bgp:mpls-l3vpn-multi-domain-switching", NB_OP_MODIFY,
			      no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_fs_local_install_yang, bgp_fs_local_install_yang_cmd,
	   "[no] local-install INTERFACE$ifname",
	   NO_STR
	   "Apply local policy routing\n"
	   "Interface name\n")
{
	char af_xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];

	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/flow-spec-config/local-install/interface[.='%s']",
		   af_xpath, ifname);

	if (no)
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, leaf, NB_OP_CREATE, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_network_yang, bgp_network_yang_cmd,
	   "[no] network <A.B.C.D/M$prefix|A.B.C.D$address [mask A.B.C.D$netmask]> [{route-map RMAP_NAME$map_name|label-index (0-1048560)$label_index|backdoor$backdoor}]",
	   NO_STR
	   "Specify a network to announce via BGP\n"
	   "IPv4 prefix\n"
	   "Network number\n"
	   "Network mask\n"
	   "Network mask\n"
	   "Route-map to modify the attributes\n"
	   "Name of the route map\n"
	   "Label index to associate with the prefix\n"
	   "Label index value\n"
	   "Specify a BGP backdoor route\n")
{
	char af_xpath[XPATH_MAXLEN];
	char net_xpath[XPATH_MAXLEN * 10];
	char leaf[XPATH_MAXLEN * 12];
	char addr_prefix_str[BUFSIZ];
	const char *pfx;
	char buf[16];

	if (address_str) {
		if (!netmask_str2prefix_str(address_str, netmask_str, addr_prefix_str,
					    sizeof(addr_prefix_str))) {
			vty_out(vty, "%% Inconsistent address and mask\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		pfx = addr_prefix_str;
	} else
		pfx = prefix_str;

	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);
	snprintfrr(net_xpath, sizeof(net_xpath), "%s/network-config[prefix='%s']", af_xpath, pfx);

	if (no) {
		nb_cli_enqueue_change(vty, net_xpath, NB_OP_DESTROY, NULL);
		return nb_cli_apply_changes(vty, NULL);
	}

	nb_cli_enqueue_change(vty, net_xpath, NB_OP_CREATE, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/backdoor", net_xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, backdoor ? "true" : "false");
	snprintfrr(leaf, sizeof(leaf), "%s/rmap-policy-export", net_xpath);
	if (map_name)
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, map_name);
	else
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/label-index", net_xpath);
	if (label_index_str) {
		snprintfrr(buf, sizeof(buf), "%" PRId64, label_index);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, buf);
	}
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(ipv6_bgp_network_yang, ipv6_bgp_network_yang_cmd,
	   "[no] network X:X::X:X/M$prefix [{route-map RMAP_NAME$map_name|label-index (0-1048560)$label_index}]",
	   NO_STR
	   "Specify a network to announce via BGP\n"
	   "IPv6 prefix\n"
	   "Route-map to modify the attributes\n"
	   "Name of the route map\n"
	   "Label index to associate with the prefix\n"
	   "Label index value\n")
{
	char af_xpath[XPATH_MAXLEN];
	char net_xpath[XPATH_MAXLEN + 256];
	char leaf[XPATH_MAXLEN + 512];
	char buf[16];

	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);
	snprintfrr(net_xpath, sizeof(net_xpath), "%s/network-config[prefix='%s']", af_xpath,
		   prefix_str);

	if (no) {
		nb_cli_enqueue_change(vty, net_xpath, NB_OP_DESTROY, NULL);
		return nb_cli_apply_changes(vty, NULL);
	}

	nb_cli_enqueue_change(vty, net_xpath, NB_OP_CREATE, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/rmap-policy-export", net_xpath);
	if (map_name)
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, map_name);
	else
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/label-index", net_xpath);
	if (label_index_str) {
		snprintfrr(buf, sizeof(buf), "%" PRId64, label_index);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, buf);
	}
	return nb_cli_apply_changes(vty, NULL);
}

ALIAS_ATTR(
	bgp_network_yang, bgp_network_yang_hidden_cmd,
	"[no] network <A.B.C.D/M$prefix|A.B.C.D$address [mask A.B.C.D$netmask]> [{route-map RMAP_NAME$map_name|label-index (0-1048560)$label_index|backdoor$backdoor}]",
	NO_STR "Specify a network to announce via BGP\n"
	       "IPv4 prefix\n"
	       "Network number\n"
	       "Network mask\n"
	       "Network mask\n"
	       "Route-map to modify the attributes\n"
	       "Name of the route map\n"
	       "Label index to associate with the prefix\n"
	       "Label index value\n"
	       "Specify a BGP backdoor route\n",
	CMD_ATTR_YANG | CMD_ATTR_HIDDEN);

DEFPY_YANG(aggregate_addressv4_yang, aggregate_addressv4_yang_cmd,
	   "[no] aggregate-address <A.B.C.D/M$prefix|A.B.C.D$addr A.B.C.D$mask> [{"
	   "as-set$as_set_s"
	   "|summary-only$summary_only"
	   "|route-map RMAP_NAME$rmap_name"
	   "|origin <egp|igp|incomplete>$origin_s"
	   "|matching-MED-only$match_med"
	   "|suppress-map RMAP_NAME$suppress_map"
	   "|upa$upa [drop$upa_drop] [max-routes (1-65535)$upa_max_routes]"
	   "}]",
	   NO_STR
	   "Configure BGP aggregate entries\n"
	   "Aggregate prefix\n"
	   "Aggregate address\n"
	   "Aggregate mask\n"
	   "Generate AS set path information\n"
	   "Filter more specific routes from updates\n"
	   "Apply route map to aggregate network\n"
	   "Route map name\n"
	   "BGP origin code\n"
	   "Remote EGP\n"
	   "Local IGP\n"
	   "Unknown heritage\n"
	   "Only aggregate routes with matching MED\n"
	   "Suppress the selected more specific routes\n"
	   "Route map with the route selectors\n"
	   "Originate UPA (Unreachable Prefix Announcement) for unreachable prefixes\n"
	   "Set D-bit in UPA Extended Community (receivers install drop entry)\n"
	   "Cap simultaneous UPA routes for this aggregate\n"
	   "Maximum number of UPA routes\n")
{
	char af_xpath[XPATH_MAXLEN];
	char agg_xpath[XPATH_MAXLEN * 10];
	char leaf[XPATH_MAXLEN * 11];
	char prefix_buf[BUFSIZ];
	const char *pfx;
	char buf[16];

	if (addr_str) {
		if (!netmask_str2prefix_str(addr_str, mask_str, prefix_buf, sizeof(prefix_buf))) {
			vty_out(vty, "%% Inconsistent address and mask\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		pfx = prefix_buf;
	} else
		pfx = prefix_str;

	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);
	snprintfrr(agg_xpath, sizeof(agg_xpath), "%s/aggregate-route[prefix='%s']", af_xpath, pfx);

	if (no) {
		nb_cli_enqueue_change(vty, agg_xpath, NB_OP_DESTROY, NULL);
		return nb_cli_apply_changes(vty, NULL);
	}

	nb_cli_enqueue_change(vty, agg_xpath, NB_OP_CREATE, NULL);

	snprintfrr(leaf, sizeof(leaf), "%s/as-set", agg_xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, as_set_s ? "true" : "false");
	snprintfrr(leaf, sizeof(leaf), "%s/summary-only", agg_xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, summary_only ? "true" : "false");
	snprintfrr(leaf, sizeof(leaf), "%s/match-med", agg_xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, match_med ? "true" : "false");

	snprintfrr(leaf, sizeof(leaf), "%s/origin", agg_xpath);
	if (origin_s)
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, origin_s);
	else
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, "unspecified");

	snprintfrr(leaf, sizeof(leaf), "%s/rmap-policy-export", agg_xpath);
	if (rmap_name)
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, rmap_name);
	else
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);

	snprintfrr(leaf, sizeof(leaf), "%s/suppress-map", agg_xpath);
	if (suppress_map)
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, suppress_map);
	else
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);

	snprintfrr(leaf, sizeof(leaf), "%s/upa", agg_xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY,
			      (upa || upa_drop || upa_max_routes_str) ? "true" : "false");
	snprintfrr(leaf, sizeof(leaf), "%s/upa-drop", agg_xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, upa_drop ? "true" : "false");
	snprintfrr(leaf, sizeof(leaf), "%s/upa-max-routes", agg_xpath);
	if (upa_max_routes_str) {
		snprintfrr(buf, sizeof(buf), "%" PRId64, upa_max_routes);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, buf);
	} else
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(aggregate_addressv6_yang, aggregate_addressv6_yang_cmd,
	   "[no] aggregate-address X:X::X:X/M$prefix [{"
	   "as-set$as_set_s"
	   "|summary-only$summary_only"
	   "|route-map RMAP_NAME$rmap_name"
	   "|origin <egp|igp|incomplete>$origin_s"
	   "|matching-MED-only$match_med"
	   "|suppress-map RMAP_NAME$suppress_map"
	   "|upa$upa [drop$upa_drop] [max-routes (1-65535)$upa_max_routes]"
	   "}]",
	   NO_STR
	   "Configure BGP aggregate entries\n"
	   "Aggregate prefix\n"
	   "Generate AS set path information\n"
	   "Filter more specific routes from updates\n"
	   "Apply route map to aggregate network\n"
	   "Route map name\n"
	   "BGP origin code\n"
	   "Remote EGP\n"
	   "Local IGP\n"
	   "Unknown heritage\n"
	   "Only aggregate routes with matching MED\n"
	   "Suppress the selected more specific routes\n"
	   "Route map with the route selectors\n"
	   "Originate UPA (Unreachable Prefix Announcement) for unreachable prefixes\n"
	   "Set D-bit in UPA Extended Community (receivers install drop entry)\n"
	   "Cap simultaneous UPA routes for this aggregate\n"
	   "Maximum number of UPA routes\n")
{
	char af_xpath[XPATH_MAXLEN];
	char agg_xpath[XPATH_MAXLEN + 256];
	char leaf[XPATH_MAXLEN + 512];
	char buf[16];

	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);
	snprintfrr(agg_xpath, sizeof(agg_xpath), "%s/aggregate-route[prefix='%s']", af_xpath,
		   prefix_str);

	if (no) {
		nb_cli_enqueue_change(vty, agg_xpath, NB_OP_DESTROY, NULL);
		return nb_cli_apply_changes(vty, NULL);
	}

	nb_cli_enqueue_change(vty, agg_xpath, NB_OP_CREATE, NULL);

	snprintfrr(leaf, sizeof(leaf), "%s/as-set", agg_xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, as_set_s ? "true" : "false");
	snprintfrr(leaf, sizeof(leaf), "%s/summary-only", agg_xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, summary_only ? "true" : "false");
	snprintfrr(leaf, sizeof(leaf), "%s/match-med", agg_xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, match_med ? "true" : "false");

	snprintfrr(leaf, sizeof(leaf), "%s/origin", agg_xpath);
	if (origin_s)
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, origin_s);
	else
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, "unspecified");

	snprintfrr(leaf, sizeof(leaf), "%s/rmap-policy-export", agg_xpath);
	if (rmap_name)
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, rmap_name);
	else
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);

	snprintfrr(leaf, sizeof(leaf), "%s/suppress-map", agg_xpath);
	if (suppress_map)
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, suppress_map);
	else
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);

	snprintfrr(leaf, sizeof(leaf), "%s/upa", agg_xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY,
			      (upa || upa_drop || upa_max_routes_str) ? "true" : "false");
	snprintfrr(leaf, sizeof(leaf), "%s/upa-drop", agg_xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, upa_drop ? "true" : "false");
	snprintfrr(leaf, sizeof(leaf), "%s/upa-max-routes", agg_xpath);
	if (upa_max_routes_str) {
		snprintfrr(buf, sizeof(buf), "%" PRId64, upa_max_routes);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, buf);
	} else
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

ALIAS_ATTR(aggregate_addressv4_yang, aggregate_addressv4_yang_hidden_cmd,
	   "[no] aggregate-address <A.B.C.D/M$prefix|A.B.C.D$addr A.B.C.D$mask> [{"
	   "as-set$as_set_s"
	   "|summary-only$summary_only"
	   "|route-map RMAP_NAME$rmap_name"
	   "|origin <egp|igp|incomplete>$origin_s"
	   "|matching-MED-only$match_med"
	   "|suppress-map RMAP_NAME$suppress_map"
	   "|upa$upa [drop$upa_drop] [max-routes (1-65535)$upa_max_routes]"
	   "}]",
	   NO_STR "Configure BGP aggregate entries\n"
		  "Aggregate prefix\n"
		  "Aggregate address\n"
		  "Aggregate mask\n"
		  "Generate AS set path information\n"
		  "Filter more specific routes from updates\n"
		  "Apply route map to aggregate network\n"
		  "Route map name\n"
		  "BGP origin code\n"
		  "Remote EGP\n"
		  "Local IGP\n"
		  "Unknown heritage\n"
		  "Only aggregate routes with matching MED\n"
		  "Suppress the selected more specific routes\n"
		  "Route map with the route selectors\n"
		  "Originate UPA (Unreachable Prefix Announcement) for unreachable prefixes\n"
		  "Set D-bit in UPA Extended Community (receivers install drop entry)\n"
		  "Cap simultaneous UPA routes for this aggregate\n"
		  "Maximum number of UPA routes\n",
	   CMD_ATTR_YANG | CMD_ATTR_HIDDEN);


/*
 * DEFUN so the C preprocessor expands MULTIPATH_NUM. A DEFPY would need
 * clippy to read config.h, which lives in the build directory.
 */
DEFUN_YANG(bgp_maxpaths_yang, bgp_maxpaths_yang_cmd,
	   "[no] maximum-paths [" CMD_RANGE_STR(1, MULTIPATH_NUM) "]",
	   NO_STR
	   "Forward packets over multiple paths\n"
	   "Number of paths\n")
{
	char af_xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	int idx = 0;

	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/use-multiple-paths/ebgp/maximum-paths", af_xpath);
	if (argv_find(argv, argc, "no", &idx))
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	else {
		idx = 0;
		if (!argv_find(argv, argc, CMD_RANGE_STR(1, MULTIPATH_NUM), &idx))
			return CMD_WARNING_CONFIG_FAILED;
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, argv[idx]->arg);
	}
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(bgp_maxpaths_ibgp_yang, bgp_maxpaths_ibgp_yang_cmd,
	   "[no] maximum-paths ibgp [" CMD_RANGE_STR(1, MULTIPATH_NUM) " [equal-cluster-length]]",
	   NO_STR
	   "Forward packets over multiple paths\n"
	   "iBGP-multipath\n"
	   "Number of paths\n"
	   "Match the cluster length\n")
{
	char af_xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	int idx = 0;
	bool cluster;

	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/use-multiple-paths/ibgp/maximum-paths", af_xpath);
	if (argv_find(argv, argc, "no", &idx)) {
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
		snprintfrr(leaf, sizeof(leaf), "%s/use-multiple-paths/ibgp/cluster-length-list",
			   af_xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	} else {
		idx = 0;
		if (!argv_find(argv, argc, CMD_RANGE_STR(1, MULTIPATH_NUM), &idx))
			return CMD_WARNING_CONFIG_FAILED;
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, argv[idx]->arg);
		cluster = argv_find(argv, argc, "equal-cluster-length", &idx);
		snprintfrr(leaf, sizeof(leaf), "%s/use-multiple-paths/ibgp/cluster-length-list",
			   af_xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, cluster ? "true" : "false");
	}
	return nb_cli_apply_changes(vty, NULL);
}

ALIAS_ATTR(bgp_maxpaths_yang, bgp_maxpaths_yang_hidden_cmd,
	   "[no] maximum-paths [" CMD_RANGE_STR(1, MULTIPATH_NUM) "$mpaths]",
	   NO_STR "Forward packets over multiple paths\n"
		  "Number of paths\n",
	   CMD_ATTR_YANG | CMD_ATTR_HIDDEN);

ALIAS_ATTR(bgp_maxpaths_ibgp_yang, bgp_maxpaths_ibgp_yang_hidden_cmd,
	   "[no] maximum-paths ibgp [" CMD_RANGE_STR(
		   1, MULTIPATH_NUM) "$mpaths [equal-cluster-length$cluster]]",
	   NO_STR "Forward packets over multiple paths\n"
		  "iBGP-multipath\n"
		  "Number of paths\n"
		  "Match the cluster length\n",
	   CMD_ATTR_YANG | CMD_ATTR_HIDDEN);

/*
 * redistribute (ipv4/ipv6 unicast)
 */
static int bgp_cli_redistribute(struct vty *vty, const char *proto, unsigned short instance,
				bool no, const char *metric_str, const char *rmap)
{
	char af_xpath[XPATH_MAXLEN];
	char red_xpath[XPATH_MAXLEN + 256];
	char leaf[XPATH_MAXLEN + 512];
	struct bgp *bgp;

	if (strmatch(proto, "table-direct")) {
		/*
		 * During XFRR batch load, router-bgp context is not pushed
		 * yet — do not abort. NB validate covers table/VRF checks.
		 */
		bgp = VTY_GET_CONTEXT(bgp);
		if (bgp) {
			if (instance == RT_TABLE_MAIN || instance == RT_TABLE_LOCAL) {
				vty_out(vty, "%% 'table-direct', can not use %u routing table\n",
					instance);
				return CMD_WARNING_CONFIG_FAILED;
			}
			if (vty->node == BGP_IPV6_NODE && bgp->vrf_id != VRF_DEFAULT) {
				vty_out(vty,
					"%% Only default BGP instance can use 'table-direct'\n");
				return CMD_WARNING_CONFIG_FAILED;
			}
		}
	}

	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);
	snprintfrr(red_xpath, sizeof(red_xpath),
		   "%s/redistribution-list[route-type='%s'][route-instance='%u']", af_xpath, proto,
		   instance);

	if (no) {
		nb_cli_enqueue_change(vty, red_xpath, NB_OP_DESTROY, NULL);
		return nb_cli_apply_changes(vty, NULL);
	}

	nb_cli_enqueue_change(vty, red_xpath, NB_OP_CREATE, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/metric", red_xpath);
	if (metric_str)
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, metric_str);
	else
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/rmap-policy-import", red_xpath);
	if (rmap)
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, rmap);
	else
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_redistribute_ipv4_yang, bgp_redistribute_ipv4_yang_cmd,
	   "[no] redistribute " FRR_IP_REDIST_STR_BGPD "$proto [{metric (0-4294967295)$metric|route-map RMAP_NAME$rmap}]",
	   NO_STR
	   "Redistribute information from another routing protocol\n"
	   FRR_IP_REDIST_HELP_STR_BGPD
	   "Metric for redistributed routes\n"
	   "Default metric\n"
	   "Route map reference\n"
	   "Pointer to route-map entries\n")
{
	return bgp_cli_redistribute(vty, proto, 0, !!no, metric_str, rmap);
}

DEFPY_YANG(bgp_redistribute_ipv4_instance_yang,
	   bgp_redistribute_ipv4_instance_yang_cmd,
	   "[no] redistribute <ospf|table|table-direct>$proto (1-65535)$instance [{metric (0-4294967295)$metric|route-map RMAP_NAME$rmap}]",
	   NO_STR
	   "Redistribute information from another routing protocol\n"
	   "Open Shortest Path First (OSPFv2)\n"
	   "Non-main Kernel Routing Table\n"
	   "Non-main Kernel Routing Table - Direct\n"
	   "Instance ID/Table ID\n"
	   "Metric for redistributed routes\n"
	   "Default metric\n"
	   "Route map reference\n"
	   "Pointer to route-map entries\n")
{
	return bgp_cli_redistribute(vty, proto, instance, !!no, metric_str, rmap);
}

DEFPY_YANG(bgp_redistribute_ipv6_yang, bgp_redistribute_ipv6_yang_cmd,
	   "[no] redistribute " FRR_IP6_REDIST_STR_BGPD "$proto [{metric (0-4294967295)$metric|route-map RMAP_NAME$rmap}]",
	   NO_STR
	   "Redistribute information from another routing protocol\n"
	   FRR_IP6_REDIST_HELP_STR_BGPD
	   "Metric for redistributed routes\n"
	   "Default metric\n"
	   "Route map reference\n"
	   "Pointer to route-map entries\n")
{
	return bgp_cli_redistribute(vty, proto, 0, !!no, metric_str, rmap);
}

DEFPY_YANG(bgp_redistribute_ipv6_table_yang,
	   bgp_redistribute_ipv6_table_yang_cmd,
	   "[no] redistribute table-direct (1-65535)$instance [{metric (0-4294967295)$metric|route-map RMAP_NAME$rmap}]",
	   NO_STR
	   "Redistribute information from another routing protocol\n"
	   "Non-main Kernel Routing Table - Direct\n"
	   "Table ID\n"
	   "Metric for redistributed routes\n"
	   "Default metric\n"
	   "Route map reference\n"
	   "Pointer to route-map entries\n")
{
	return bgp_cli_redistribute(vty, "table-direct", instance, !!no, metric_str, rmap);
}

ALIAS_ATTR(bgp_redistribute_ipv4_yang, bgp_redistribute_ipv4_yang_hidden_cmd,
	   "[no] redistribute " FRR_IP_REDIST_STR_BGPD
	   "$proto [{metric (0-4294967295)$metric|route-map RMAP_NAME$rmap}]",
	   NO_STR
	   "Redistribute information from another routing protocol\n" FRR_IP_REDIST_HELP_STR_BGPD
	   "Metric for redistributed routes\n"
	   "Default metric\n"
	   "Route map reference\n"
	   "Pointer to route-map entries\n",
	   CMD_ATTR_YANG | CMD_ATTR_HIDDEN);

ALIAS_ATTR(
	bgp_redistribute_ipv4_instance_yang, bgp_redistribute_ipv4_instance_yang_hidden_cmd,
	"[no] redistribute <ospf|table|table-direct>$proto (1-65535)$instance [{metric (0-4294967295)$metric|route-map RMAP_NAME$rmap}]",
	NO_STR "Redistribute information from another routing protocol\n"
	       "Open Shortest Path First (OSPFv2)\n"
	       "Non-main Kernel Routing Table\n"
	       "Non-main Kernel Routing Table - Direct\n"
	       "Instance ID/Table ID\n"
	       "Metric for redistributed routes\n"
	       "Default metric\n"
	       "Route map reference\n"
	       "Pointer to route-map entries\n",
	CMD_ATTR_YANG | CMD_ATTR_HIDDEN);

/*
 * distance (ipv4/ipv6 unicast; multicast remains classic)
 */
DEFPY_YANG(bgp_distance_yang, bgp_distance_yang_cmd,
	   "[no] distance bgp [(1-255)$ext (1-255)$internal (1-255)$local]",
	   NO_STR
	   "Define an administrative distance\n"
	   "BGP distance\n"
	   "Distance for routes external to the AS\n"
	   "Distance for routes internal to the AS\n"
	   "Distance for local routes\n")
{
	char af_xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	char ext_buf[8], int_buf[8], local_buf[8];

	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);

	if (no) {
		snprintfrr(leaf, sizeof(leaf), "%s/admin-distance/external", af_xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
		snprintfrr(leaf, sizeof(leaf), "%s/admin-distance/internal", af_xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
		snprintfrr(leaf, sizeof(leaf), "%s/admin-distance/local", af_xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
		return nb_cli_apply_changes(vty, NULL);
	}

	if (!ext_str || !internal_str || !local_str)
		return CMD_WARNING_CONFIG_FAILED;

	/*
	 * Distinct buffers: nb_cli_enqueue_change stores the value pointer
	 * until apply; reusing one buf made all three leaves the last value.
	 */
	snprintfrr(leaf, sizeof(leaf), "%s/admin-distance/external", af_xpath);
	snprintfrr(ext_buf, sizeof(ext_buf), "%" PRId64, ext);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, ext_buf);
	snprintfrr(leaf, sizeof(leaf), "%s/admin-distance/internal", af_xpath);
	snprintfrr(int_buf, sizeof(int_buf), "%" PRId64, internal);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, int_buf);
	snprintfrr(leaf, sizeof(leaf), "%s/admin-distance/local", af_xpath);
	snprintfrr(local_buf, sizeof(local_buf), "%" PRId64, local);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, local_buf);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_distance_source_yang, bgp_distance_source_yang_cmd,
	   "[no] distance (1-255)$distance A.B.C.D/M$prefix [WORD$acl]",
	   NO_STR
	   "Define an administrative distance\n"
	   "Administrative distance\n"
	   "IP source prefix\n"
	   "Access list name\n")
{
	char af_xpath[XPATH_MAXLEN];
	char route_xpath[XPATH_MAXLEN + 256];
	char leaf[XPATH_MAXLEN + 512];
	char buf[8];

	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);
	snprintfrr(route_xpath, sizeof(route_xpath), "%s/admin-distance-route[prefix='%s']",
		   af_xpath, prefix_str);

	if (no) {
		nb_cli_enqueue_change(vty, route_xpath, NB_OP_DESTROY, NULL);
		return nb_cli_apply_changes(vty, NULL);
	}

	nb_cli_enqueue_change(vty, route_xpath, NB_OP_CREATE, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/distance", route_xpath);
	snprintfrr(buf, sizeof(buf), "%" PRId64, distance);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, buf);
	snprintfrr(leaf, sizeof(leaf), "%s/access-list", route_xpath);
	if (acl)
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, acl);
	else
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_distance_source_v6_yang, bgp_distance_source_v6_yang_cmd,
	   "[no] distance (1-255)$distance X:X::X:X/M$prefix [WORD$acl]",
	   NO_STR
	   "Define an administrative distance\n"
	   "Administrative distance\n"
	   "IP source prefix\n"
	   "Access list name\n")
{
	char af_xpath[XPATH_MAXLEN];
	char route_xpath[XPATH_MAXLEN + 256];
	char leaf[XPATH_MAXLEN + 512];
	char buf[8];

	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);
	snprintfrr(route_xpath, sizeof(route_xpath), "%s/admin-distance-route[prefix='%s']",
		   af_xpath, prefix_str);

	if (no) {
		nb_cli_enqueue_change(vty, route_xpath, NB_OP_DESTROY, NULL);
		return nb_cli_apply_changes(vty, NULL);
	}

	nb_cli_enqueue_change(vty, route_xpath, NB_OP_CREATE, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/distance", route_xpath);
	snprintfrr(buf, sizeof(buf), "%" PRId64, distance);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, buf);
	snprintfrr(leaf, sizeof(leaf), "%s/access-list", route_xpath);
	if (acl)
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, acl);
	else
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

ALIAS_ATTR(bgp_distance_yang, bgp_distance_yang_hidden_cmd,
	   "[no] distance bgp [(1-255)$ext (1-255)$internal (1-255)$local]",
	   NO_STR "Define an administrative distance\n"
		  "BGP distance\n"
		  "Distance for routes external to the AS\n"
		  "Distance for routes internal to the AS\n"
		  "Distance for local routes\n",
	   CMD_ATTR_YANG | CMD_ATTR_HIDDEN);

ALIAS_ATTR(bgp_distance_source_yang, bgp_distance_source_yang_hidden_cmd,
	   "[no] distance (1-255)$distance A.B.C.D/M$prefix [WORD$acl]",
	   NO_STR "Define an administrative distance\n"
		  "Administrative distance\n"
		  "IP source prefix\n"
		  "Access list name\n",
	   CMD_ATTR_YANG | CMD_ATTR_HIDDEN);

DEFPY_YANG(bgp_table_map_yang, bgp_table_map_yang_cmd,
	   "[no] table-map RMAP_NAME$name",
	   NO_STR
	   "BGP table to RIB route download filter\n"
	   "Name of the route map\n")
{
	char af_xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];

	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/filter-config/rmap-export", af_xpath);
	if (no)
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, name);
	return nb_cli_apply_changes(vty, NULL);
}

ALIAS_ATTR(bgp_table_map_yang, bgp_table_map_yang_hidden_cmd, "[no] table-map RMAP_NAME$name",
	   NO_STR "BGP table to RIB route download filter\n"
		  "Name of the route map\n",
	   CMD_ATTR_YANG | CMD_ATTR_HIDDEN);

DEFPY_YANG(bgp_dampening_yang, bgp_dampening_yang_cmd,
	   "[no] bgp dampening [(1-45)$half [(1-20000)$reuse (1-50000)$suppress (1-255)$max]]",
	   NO_STR
	   "BGP Specific commands\n"
	   "Enable route-flap dampening\n"
	   "Half-life time for the penalty\n"
	   "Value to start reusing a route\n"
	   "Value to start suppressing a route\n"
	   "Maximum duration to suppress a stable route\n")
{
	char af_xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	char half_buf[16], reuse_buf[16], suppress_buf[16], max_buf[16];
	unsigned int half_min, reuse_val, suppress_val, max_min;

	if (!no && suppress_str && reuse_str && (unsigned int)suppress < (unsigned int)reuse) {
		vty_out(vty, "Suppress value cannot be less than reuse value\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);

	if (no) {
		snprintfrr(leaf, sizeof(leaf), "%s/route-flap-dampening/enable", af_xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
		snprintfrr(leaf, sizeof(leaf), "%s/route-flap-dampening/reach-decay", af_xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
		snprintfrr(leaf, sizeof(leaf), "%s/route-flap-dampening/reuse-above", af_xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
		snprintfrr(leaf, sizeof(leaf), "%s/route-flap-dampening/suppress-above", af_xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
		snprintfrr(leaf, sizeof(leaf), "%s/route-flap-dampening/unreach-decay", af_xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
		return nb_cli_apply_changes(vty, NULL);
	}

	half_min = half_str ? (unsigned int)half : DEFAULT_HALF_LIFE;
	reuse_val = reuse_str ? (unsigned int)reuse : DEFAULT_REUSE;
	suppress_val = suppress_str ? (unsigned int)suppress : DEFAULT_SUPPRESS;
	max_min = max_str ? (unsigned int)max : (4 * half_min);

	snprintfrr(leaf, sizeof(leaf), "%s/route-flap-dampening/enable", af_xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, "true");

	snprintfrr(leaf, sizeof(leaf), "%s/route-flap-dampening/reach-decay", af_xpath);
	snprintfrr(half_buf, sizeof(half_buf), "%u", half_min);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, half_buf);

	snprintfrr(leaf, sizeof(leaf), "%s/route-flap-dampening/reuse-above", af_xpath);
	snprintfrr(reuse_buf, sizeof(reuse_buf), "%u", reuse_val);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, reuse_buf);

	snprintfrr(leaf, sizeof(leaf), "%s/route-flap-dampening/suppress-above", af_xpath);
	snprintfrr(suppress_buf, sizeof(suppress_buf), "%u", suppress_val);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, suppress_buf);

	snprintfrr(leaf, sizeof(leaf), "%s/route-flap-dampening/unreach-decay", af_xpath);
	snprintfrr(max_buf, sizeof(max_buf), "%u", max_min);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, max_buf);

	return nb_cli_apply_changes(vty, NULL);
}

ALIAS_ATTR(bgp_dampening_yang, bgp_dampening_yang_hidden_cmd,
	   "[no] bgp dampening [(1-45)$half [(1-20000)$reuse (1-50000)$suppress (1-255)$max]]",
	   NO_STR "BGP Specific commands\n"
		  "Enable route-flap dampening\n"
		  "Half-life time for the penalty\n"
		  "Value to start reusing a route\n"
		  "Value to start suppressing a route\n"
		  "Maximum duration to suppress a stable route\n",
	   CMD_ATTR_YANG | CMD_ATTR_HIDDEN);

DEFPY_YANG(upa_originate_all_yang, upa_originate_all_yang_cmd,
	   "[no] upa originate-all",
	   NO_STR
	   "Unreachable Prefix Announcement\n"
	   "Originate UPA routes for ALL unreachable prefixes (not just under aggregates)\n")
{
	char af_xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];

	if (bgp_node_safi(vty) != SAFI_UNICAST) {
		vty_out(vty, "%% Global UPA origination is only supported for unicast SAFI\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/upa/originate-all", af_xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(upa_max_routes_yang, upa_max_routes_yang_cmd,
	   "[no] upa max-routes [(1-4294967295)$max]",
	   NO_STR
	   "Unreachable Prefix Announcement\n"
	   "Maximum number of simultaneous global UPA routes\n"
	   "Maximum count\n")
{
	char af_xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	char buf[16];

	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/upa/max-routes", af_xpath);
	if (no)
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	else {
		if (!max_str)
			return CMD_WARNING_CONFIG_FAILED;
		snprintfrr(buf, sizeof(buf), "%" PRId64, max);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, buf);
	}
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(upa_drop_yang, upa_drop_yang_cmd,
	   "[no] upa drop",
	   NO_STR
	   "Unreachable Prefix Announcement\n"
	   "Set D-bit in global UPA Extended Community (receivers install drop/blackhole entry)\n")
{
	char af_xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];

	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/upa/drop", af_xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_af_nexthop_prefer_global_yang,
	   bgp_af_nexthop_prefer_global_yang_cmd,
	   "[no] nexthop prefer-global",
	   NO_STR
	   "Nexthop\n"
	   "Prefer global over link-local if both exist\n")
{
	char af_xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];

	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/prefer-global", af_xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_evpn_advertise_all_vni_yang,
	   bgp_evpn_advertise_all_vni_yang_cmd,
	   "[no] advertise-all-vni",
	   NO_STR
	   "Advertise All local VNIs\n")
{
	char af_xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];

	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/advertise-all-vni", af_xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

/* Deprecated: use "auto-route-target both rfc8365-compatible". */
DEFPY_YANG(bgp_evpn_autort_rfc8365_yang, bgp_evpn_autort_rfc8365_yang_cmd,
	   "[no] autort rfc8365-compatible",
	   NO_STR
	   "Auto-derivation of RT\n"
	   "Auto-derivation of RT using RFC8365\n")
{
	char af_xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	const char *dir;

	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);
	for (dir = "import"; dir; dir = strmatch(dir, "import") ? "export" : NULL) {
		snprintfrr(leaf, sizeof(leaf), "%s/%s-autort-rfc8365-compatible", af_xpath, dir);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, no ? "false" : "true");
	}
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_evpn_advertise_default_gw_yang,
	   bgp_evpn_advertise_default_gw_yang_cmd,
	   "[no] advertise-default-gw",
	   NO_STR
	   "Advertise All default g/w mac-ip routes in EVPN\n")
{
	char af_xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];

	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/advertise-default-gateway", af_xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_evpn_advertise_svi_ip_yang,
	   bgp_evpn_advertise_svi_ip_yang_cmd,
	   "[no] advertise-svi-ip",
	   NO_STR
	   "Advertise svi mac-ip routes in EVPN\n")
{
	char af_xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];

	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/advertise-svi-ip", af_xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_evpn_resolve_overlay_yang,
	   bgp_evpn_resolve_overlay_yang_cmd,
	   "[no] enable-resolve-overlay-index",
	   NO_STR
	   "Enable Recursive Resolution of type-5 route overlay index\n")
{
	char af_xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];

	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/enable-resolve-overlay-index", af_xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_evpn_flooding_yang, bgp_evpn_flooding_yang_cmd,
	   "[no] flooding <disable$disable|head-end-replication$her>",
	   NO_STR
	   "Specify handling for BUM packets\n"
	   "Do not flood any BUM packets\n"
	   "Flood BUM packets using head-end replication\n")
{
	char af_xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	const char *val;

	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/flooding", af_xpath);

	if (no || her)
		val = "head-end-replication";
	else if (disable)
		val = "disable";
	else
		return CMD_WARNING_CONFIG_FAILED;

	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, val);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_evpn_macvrf_soo_yang, bgp_evpn_macvrf_soo_yang_cmd,
	   "[no] mac-vrf soo [ASN:NN_OR_IP-ADDRESS:NN$soo]",
	   NO_STR
	   "EVPN MAC-VRF\n"
	   "Site-of-Origin extended community\n"
	   "VPN extended community\n")
{
	char af_xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];

	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/mac-vrf-site-of-origin", af_xpath);

	if (no)
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	else {
		if (!soo) {
			vty_out(vty, "%% Incomplete command\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, soo);
	}
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_evpn_dad_yang, bgp_evpn_dad_yang_cmd,
	   "[no] dup-addr-detection [max-moves (2-1000)$max_moves time (2-1800)$time | freeze <permanent$permanent |(30-3600)$freeze_time>]",
	   NO_STR
	   "Duplicate address detection\n"
	   "Max allowed moves before address detected as duplicate\n"
	   "Num of max allowed moves (2-1000) default 5\n"
	   "Duplicate address detection time\n"
	   "Time in seconds (2-1800) default 180\n"
	   "Duplicate address detection freeze\n"
	   "Duplicate address detection permanent freeze\n"
	   "Duplicate address detection freeze time (30-3600)\n")
{
	char af_xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	char moves_buf[16], time_buf[16], freeze_buf[16];

	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);

	if (no) {
		if (!max_moves_str && !time_str && !permanent && !freeze_time_str) {
			snprintfrr(leaf, sizeof(leaf), "%s/duplicate-address-detection/enable",
				   af_xpath);
			nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, "false");
			snprintfrr(leaf, sizeof(leaf), "%s/duplicate-address-detection/max-moves",
				   af_xpath);
			nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
			snprintfrr(leaf, sizeof(leaf), "%s/duplicate-address-detection/time",
				   af_xpath);
			nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
			snprintfrr(leaf, sizeof(leaf),
				   "%s/duplicate-address-detection/freeze-time", af_xpath);
			nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
			snprintfrr(leaf, sizeof(leaf),
				   "%s/duplicate-address-detection/freeze-permanent", af_xpath);
			nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
			return nb_cli_apply_changes(vty, NULL);
		}
		if (max_moves_str || time_str) {
			snprintfrr(leaf, sizeof(leaf), "%s/duplicate-address-detection/max-moves",
				   af_xpath);
			nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
			snprintfrr(leaf, sizeof(leaf), "%s/duplicate-address-detection/time",
				   af_xpath);
			nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
			return nb_cli_apply_changes(vty, NULL);
		}
		snprintfrr(leaf, sizeof(leaf), "%s/duplicate-address-detection/freeze-time",
			   af_xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
		snprintfrr(leaf, sizeof(leaf), "%s/duplicate-address-detection/freeze-permanent",
			   af_xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
		return nb_cli_apply_changes(vty, NULL);
	}

	snprintfrr(leaf, sizeof(leaf), "%s/duplicate-address-detection/enable", af_xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, "true");

	if (max_moves_str && time_str) {
		snprintfrr(leaf, sizeof(leaf), "%s/duplicate-address-detection/max-moves",
			   af_xpath);
		snprintfrr(moves_buf, sizeof(moves_buf), "%" PRId64, max_moves);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, moves_buf);
		snprintfrr(leaf, sizeof(leaf), "%s/duplicate-address-detection/time", af_xpath);
		snprintfrr(time_buf, sizeof(time_buf), "%" PRId64, time);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, time_buf);
	}

	if (permanent) {
		snprintfrr(leaf, sizeof(leaf), "%s/duplicate-address-detection/freeze-time",
			   af_xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
		snprintfrr(leaf, sizeof(leaf), "%s/duplicate-address-detection/freeze-permanent",
			   af_xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_CREATE, NULL);
	} else if (freeze_time_str) {
		snprintfrr(leaf, sizeof(leaf), "%s/duplicate-address-detection/freeze-permanent",
			   af_xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
		snprintfrr(leaf, sizeof(leaf), "%s/duplicate-address-detection/freeze-time",
			   af_xpath);
		snprintfrr(freeze_buf, sizeof(freeze_buf), "%" PRId64, freeze_time);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, freeze_buf);
	}

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_evpn_use_es_l3nhg_yang, bgp_evpn_use_es_l3nhg_yang_cmd,
	   "[no] use-es-l3nhg",
	   NO_STR
	   "use L3 nexthop group for host routes with ES destination\n")
{
	char af_xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];

	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/multihoming/use-es-l3nhg", af_xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_evpn_disable_ead_evi_rx_yang,
	   bgp_evpn_disable_ead_evi_rx_yang_cmd,
	   "[no] disable-ead-evi-rx",
	   NO_STR
	   "Activate PE on EAD-ES even if EAD-EVI is not received\n")
{
	char af_xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];

	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/multihoming/disable-ead-evi-rx", af_xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_evpn_disable_ead_evi_tx_yang,
	   bgp_evpn_disable_ead_evi_tx_yang_cmd,
	   "[no] disable-ead-evi-tx",
	   NO_STR
	   "Don't advertise EAD-EVI for local ESs\n")
{
	char af_xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];

	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/multihoming/disable-ead-evi-tx", af_xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_evpn_ead_es_frag_yang, bgp_evpn_ead_es_frag_yang_cmd,
	   "[no] ead-es-frag evi-limit (1-1000)$limit",
	   NO_STR
	   "EAD ES fragment config\n"
	   "EVIs per-fragment\n"
	   "limit\n")
{
	char af_xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	char buf[16];

	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/multihoming/ead-es-fragment-evi-limit", af_xpath);
	if (no)
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	else {
		snprintfrr(buf, sizeof(buf), "%" PRId64, limit);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, buf);
	}
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_evpn_default_originate_yang,
	   bgp_evpn_default_originate_yang_cmd,
	   "[no] default-originate <ipv4$afi|ipv6$afi>",
	   NO_STR
	   "originate a default route\n"
	   "ipv4 address family\n"
	   "ipv6 address family\n")
{
	char af_xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];

	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/default-originate/%s", af_xpath, afi);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_evpn_advertise_type5_yang,
	   bgp_evpn_advertise_type5_yang_cmd,
	   "[no] advertise <ipv4$afi|ipv6$afi> <unicast|vpn>$safi_str [gateway-ip$gw_ip] [route-map RMAP_NAME$rmap] [skip-evpn-imported$skip_evpn_imported]",
	   NO_STR
	   "Advertise prefix routes\n"
	   "IPv4 address family\n"
	   "IPv6 address family\n"
	   "Unicast Address Family\n"
	   "VPN Address Family\n"
	   "advertise gateway IP overlay index\n"
	   "route-map for filtering specific routes\n"
	   "Name of the route map\n"
	   "Do not advertise routes imported from EVPN as Type-5 routes\n")
{
	char af_xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	char check[XPATH_MAXLEN + 256];
	char cont[32];
	bool is_unicast = strmatch(safi_str, "unicast");

	if (!is_unicast && gw_ip) {
		vty_out(vty, "%% gateway-ip overlay index is only supported for unicast SAFI\n");
		return CMD_WARNING;
	}

	if (!is_unicast && skip_evpn_imported) {
		vty_out(vty, "%% skip-evpn-imported is only supported for unicast SAFI\n");
		return CMD_WARNING;
	}

	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);

	snprintfrr(cont, sizeof(cont), "%s-%s", afi, safi_str);

	if (no) {
		/* No options: disable Type-5 export along with all options. */
		if (!gw_ip && !rmap && !skip_evpn_imported) {
			snprintfrr(leaf, sizeof(leaf), "%s/ip-vrf/%s/enable", af_xpath, cont);
			nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, "false");
			snprintfrr(leaf, sizeof(leaf), "%s/ip-vrf/%s/route-map", af_xpath, cont);
			nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
			if (is_unicast) {
				snprintfrr(leaf, sizeof(leaf), "%s/ip-vrf/%s/gateway-ip", af_xpath,
					   cont);
				nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
				snprintfrr(leaf, sizeof(leaf), "%s/ip-vrf/%s/skip-evpn-imported",
					   af_xpath, cont);
				nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
			}
			return nb_cli_apply_changes(vty, NULL);
		}

		/* Remove only the named options and keep Type-5 export enabled. */
		if (gw_ip) {
			snprintfrr(leaf, sizeof(leaf), "%s/ip-vrf/%s/gateway-ip", af_xpath, cont);
			nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
		}
		if (skip_evpn_imported) {
			snprintfrr(leaf, sizeof(leaf), "%s/ip-vrf/%s/skip-evpn-imported", af_xpath,
				   cont);
			nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
		}
		if (rmap) {
			const struct lyd_node *dnode;

			/* Only remove the route-map if it is the configured one. */
			snprintfrr(check, sizeof(check), "%s%s/ip-vrf/%s/route-map",
				   VTY_CURR_XPATH, af_xpath + 1, cont);
			dnode = yang_dnode_get(vty->candidate_config->dnode, check);
			if (dnode && strmatch(yang_dnode_get_string(dnode, NULL), rmap)) {
				snprintfrr(leaf, sizeof(leaf), "%s/ip-vrf/%s/route-map", af_xpath,
					   cont);
				nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
			}
		}
		return nb_cli_apply_changes(vty, NULL);
	}

	/* Omitted options are left as configured. */
	snprintfrr(leaf, sizeof(leaf), "%s/ip-vrf/%s/enable", af_xpath, cont);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, "true");
	if (gw_ip) {
		snprintfrr(leaf, sizeof(leaf), "%s/ip-vrf/%s/gateway-ip", af_xpath, cont);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, "true");
	}
	if (rmap) {
		snprintfrr(leaf, sizeof(leaf), "%s/ip-vrf/%s/route-map", af_xpath, cont);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, rmap);
	}
	if (skip_evpn_imported) {
		snprintfrr(leaf, sizeof(leaf), "%s/ip-vrf/%s/skip-evpn-imported", af_xpath, cont);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, "true");
	}

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_evpn_advertise_pip_yang, bgp_evpn_advertise_pip_yang_cmd,
	   "[no] advertise-pip [ip A.B.C.D$ip [mac <X:X:X:X:X:X|X:X:X:X:X:X/M>$mac]]",
	   NO_STR
	   "evpn system primary IP\n"
	   IP_STR
	   "ip address\n"
	   MAC_STR MAC_STR MAC_STR)
{
	char af_xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	char macbuf[PREFIX_STRLEN];

	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);

	if (no) {
		if (!ip_str) {
			snprintfrr(leaf, sizeof(leaf), "%s/advertise-pip/enable", af_xpath);
			nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, "false");
			snprintfrr(leaf, sizeof(leaf), "%s/advertise-pip/system-ip", af_xpath);
			nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
			snprintfrr(leaf, sizeof(leaf), "%s/advertise-pip/system-mac", af_xpath);
			nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
		} else {
			snprintfrr(leaf, sizeof(leaf), "%s/advertise-pip/system-ip", af_xpath);
			nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
			snprintfrr(leaf, sizeof(leaf), "%s/advertise-pip/system-mac", af_xpath);
			nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
		}
		return nb_cli_apply_changes(vty, NULL);
	}

	snprintfrr(leaf, sizeof(leaf), "%s/advertise-pip/enable", af_xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, "true");

	snprintfrr(leaf, sizeof(leaf), "%s/advertise-pip/system-ip", af_xpath);
	if (ip_str)
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, ip_str);
	else
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);

	snprintfrr(leaf, sizeof(leaf), "%s/advertise-pip/system-mac", af_xpath);
	if (mac_str) {
		prefix_mac2str(&mac->eth_addr, macbuf, sizeof(macbuf));
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, macbuf);
	} else
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_evpn_ead_es_rt_yang, bgp_evpn_ead_es_rt_yang_cmd,
	   "[no] ead-es-route-target export RT$rt",
	   NO_STR
	   "EAD ES Route Target\n"
	   "export\n"
	   "Route target (A.B.C.D:MN|EF:OPQR|GHJK:MN)\n")
{
	char af_xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];

	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/multihoming/ead-es-export-route-target[.='%s']",
		   af_xpath, rt);

	if (no)
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, leaf, NB_OP_CREATE, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_evpn_vrf_rd_yang, bgp_evpn_vrf_rd_yang_cmd,
	   "[no] rd ASN:NN_OR_IP-ADDRESS:NN$rd",
	   NO_STR
	   EVPN_RT_DIST_HELP_STR
	   EVPN_ASN_IP_HELP_STR)
{
	char af_xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	struct bgp *bgp_vrf;
	struct prefix_rd prd;

	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	snprintfrr(leaf, sizeof(leaf), "%s/ip-vrf/rd", af_xpath);

	if (no) {
		bgp_vrf = VTY_GET_CONTEXT(bgp);
		if (!bgp_vrf)
			return CMD_WARNING;
		if (!str2prefix_rd(rd, &prd)) {
			vty_out(vty, "%% Malformed Route Distinguisher\n");
			return CMD_WARNING;
		}
		if (!is_vrf_rd_configured(bgp_vrf)) {
			vty_out(vty, "%% RD is not configured for this VRF\n");
			return CMD_WARNING;
		}
		if (!bgp_evpn_vrf_rd_matches_existing(bgp_vrf, &prd)) {
			vty_out(vty,
				"%% RD specified does not match configuration for this VRF\n");
			return CMD_WARNING;
		}
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
		return nb_cli_apply_changes(vty, NULL);
	}

	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, rd);
	return nb_cli_apply_changes(vty, NULL);
}

/* Installed on BGP_NODE only. The AF helper would target ipv4-unicast here. */
DEFPY_YANG(no_bgp_evpn_vrf_rd_without_val_yang, no_bgp_evpn_vrf_rd_without_val_yang_cmd,
	   "no rd",
	   NO_STR
	   EVPN_RT_DIST_HELP_STR)
{
	struct bgp *bgp_vrf = VTY_GET_CONTEXT(bgp);

	if (!bgp_vrf)
		return CMD_WARNING;
	if (!is_vrf_rd_configured(bgp_vrf)) {
		vty_out(vty, "%% RD is not configured for this VRF\n");
		return CMD_WARNING;
	}
	nb_cli_enqueue_change(
		vty,
		"./global/afi-safis/afi-safi[afi-safi-name='frr-routing:l2vpn-evpn']/l2vpn-evpn/ip-vrf/rd",
		NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

/*
 * One route-target change queued by the command now in progress. The
 * candidate does not show it until the queue is applied, so a repeat in
 * the same RTLIST has to be answered from this list.
 */
struct bgp_cli_rt_pend {
	const char *rt;
	bool import;
	bool export;
	bool add;
};

static bool bgp_cli_rt_pend_state(const struct bgp_cli_rt_pend *pend, int npend, const char *rt,
				  bool import, bool *known)
{
	bool present = false;

	*known = false;
	for (int i = 0; i < npend; i++) {
		if (!strmatch(pend[i].rt, rt))
			continue;
		if (import ? !pend[i].import : !pend[i].export)
			continue;
		*known = true;
		present = pend[i].add;
	}
	return present;
}

/* True when @rt is configured for this direction, including this command. */
static bool bgp_cli_rt_is_set(struct vty *vty, const struct bgp_cli_rt_pend *pend, int npend,
			      const char *abs_base, const char *leaf, const char *rt, bool import)
{
	char xpath[XPATH_MAXLEN];
	bool known;

	if (bgp_cli_rt_pend_state(pend, npend, rt, import, &known))
		return true;
	if (known)
		return false;
	if (!vty->candidate_config || !vty->candidate_config->dnode)
		return false;

	snprintfrr(xpath, sizeof(xpath), "%s/%s[.='%s']", abs_base, leaf, rt);
	return yang_dnode_exists(vty->candidate_config->dnode, xpath);
}

/*
 * Apply an RTLIST the way the classic CLI did. An RT that is already
 * configured, or repeated in this list, is skipped and warned. "both"
 * warns on add only when every requested direction is already present,
 * and on delete only when none of them are; the missing or present
 * direction is still changed. @scope is "VRF" or "VNI" (the warning
 * text). @rel_base is the enqueue prefix, @abs_base the same node on the
 * candidate. Remaining entries are still applied.
 */
static int bgp_evpn_rtlist_apply(struct vty *vty, bool no, bool do_import, bool do_export,
				 const char *scope, const char *rel_base, const char *abs_base,
				 const char *leaf_import, const char *leaf_export,
				 struct cmd_token **argv, int idx, int argc)
{
	struct bgp_cli_rt_pend *pend;
	char leaf[XPATH_MAXLEN];
	bool warned = false;
	int npend = 0;
	int ret;

	/* At most one entry per RT in the list. */
	pend = XCALLOC(MTYPE_TMP, sizeof(*pend) * (argc - idx > 0 ? argc - idx : 1));

	for (; idx < argc; idx++) {
		const char *rt = argv[idx]->arg;
		bool have_import = false, have_export = false;
		bool ch_import, ch_export;

		if (do_import)
			have_import = bgp_cli_rt_is_set(vty, pend, npend, abs_base, leaf_import,
							rt, true);
		if (do_export)
			have_export = bgp_cli_rt_is_set(vty, pend, npend, abs_base, leaf_export,
							rt, false);

		if (!no) {
			ch_import = do_import && !have_import;
			ch_export = do_export && !have_export;
			if (!ch_import && !ch_export) {
				vty_out(vty, "%% RT specified already configured for this %s: %s\n",
					scope, rt);
				warned = true;
				continue;
			}
		} else {
			ch_import = do_import && have_import;
			ch_export = do_export && have_export;
			if (!ch_import && !ch_export) {
				vty_out(vty,
					"%% RT specified does not match configuration for this %s: %s\n",
					scope, rt);
				warned = true;
				continue;
			}
		}

		if (ch_import) {
			snprintfrr(leaf, sizeof(leaf), "%s/%s[.='%s']", rel_base, leaf_import, rt);
			nb_cli_enqueue_change(vty, leaf, no ? NB_OP_DESTROY : NB_OP_CREATE, NULL);
		}
		if (ch_export) {
			snprintfrr(leaf, sizeof(leaf), "%s/%s[.='%s']", rel_base, leaf_export, rt);
			nb_cli_enqueue_change(vty, leaf, no ? NB_OP_DESTROY : NB_OP_CREATE, NULL);
		}
		pend[npend].rt = rt;
		pend[npend].import = ch_import;
		pend[npend].export = ch_export;
		pend[npend].add = !no;
		npend++;
	}

	XFREE(MTYPE_TMP, pend);

	ret = nb_cli_apply_changes(vty, NULL);
	if (ret != CMD_SUCCESS)
		return ret;
	return warned ? CMD_WARNING : CMD_SUCCESS;
}

DEFPY_YANG(bgp_evpn_vrf_rt_yang, bgp_evpn_vrf_rt_yang_cmd,
	   "[no] route-target <both|import|export>$type RTLIST...",
	   NO_STR
	   "Route Target\n"
	   "import and export\n"
	   "import\n"
	   "export\n"
	   "Space separated route target list (A.B.C.D:MN|EF:OPQR|GHJK:MN)\n")
{
	char af_xpath[XPATH_MAXLEN];
	bool do_import = false;
	bool do_export = false;
	int idx = 0;
	int i;

	if (strmatch(type, "import"))
		do_import = true;
	else if (strmatch(type, "export"))
		do_export = true;
	else if (strmatch(type, "both")) {
		do_import = true;
		do_export = true;
	} else {
		vty_out(vty, "%% Invalid Route Target type\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	argv_find(argv, argc, "RTLIST", &idx);
	if (!idx) {
		vty_out(vty, "%% Missing RTLIST\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	for (i = idx; i < argc; i++) {
		if (argv[i]->arg[0] == '*' && do_export) {
			vty_out(vty, "%% Wildcard '*' only applicable for import\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);

	{
		char abs_base[XPATH_MAXLEN];

		/* af_xpath is relative ("./..."); the candidate lookup is absolute. */
		snprintfrr(abs_base, sizeof(abs_base), "%s%s", VTY_CURR_XPATH, af_xpath + 1);
		return bgp_evpn_rtlist_apply(vty, !!no, do_import, do_export, "VRF", af_xpath,
					     abs_base, "ip-vrf/import-route-target",
					     "ip-vrf/export-route-target", argv, idx, argc);
	}
}

/*
 * Shared handler for "[no] auto-route-target" under the EVPN VRF (@vrf) or
 * an L2VNI. @type is "both|import|export" (NULL means both for the no form),
 * @mode is an add-mode keyword or "rfc8365-compatible" (VRF only).
 */
static int bgp_evpn_autort_cli(struct vty *vty, bool vrf, bool no, const char *type,
			       const char *mode)
{
	static const char *const dirs[] = { "import", "export" };
	char af_xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool rfc = mode && strmatch(mode, "rfc8365-compatible");
	bool sel[2];

	sel[0] = !type || strmatch(type, "import") || strmatch(type, "both");
	sel[1] = !type || strmatch(type, "export") || strmatch(type, "both");

	if (vrf) {
		bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
		if (!no)
			nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);
	}

	for (int i = 0; i < 2; i++) {
		if (!sel[i])
			continue;

		if (rfc) {
			snprintfrr(leaf, sizeof(leaf), "%s/%s-autort-rfc8365-compatible", af_xpath,
				   dirs[i]);
			nb_cli_enqueue_change(vty, leaf, no ? NB_OP_DESTROY : NB_OP_MODIFY,
					      no ? NULL : "true");
			continue;
		}

		if (vrf)
			snprintfrr(leaf, sizeof(leaf), "%s/ip-vrf/%s-auto-route-target", af_xpath,
				   dirs[i]);
		else
			snprintfrr(leaf, sizeof(leaf), "./%s-auto-route-target", dirs[i]);

		if (!no) {
			nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, mode);
			continue;
		}

		/*
		 * With an explicit mode only clear a matching configuration;
		 * without one clear whatever is configured.
		 */
		if (mode) {
			char cur_xpath[XPATH_MAXLEN * 2];
			const struct lyd_node *cur;

			snprintfrr(cur_xpath, sizeof(cur_xpath), "%s%s", VTY_CURR_XPATH, leaf + 1);
			cur = yang_dnode_get(vty->candidate_config->dnode, cur_xpath);
			if (cur && !strmatch(yang_dnode_get_string(cur, NULL), mode))
				continue;
		}
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);

		if (vrf && !mode) {
			snprintfrr(leaf, sizeof(leaf), "%s/%s-autort-rfc8365-compatible", af_xpath,
				   dirs[i]);
			nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
		}
	}

	return nb_cli_apply_changes(vty, NULL);
}

#define AUTORT_HELP_STR                                                                           \
	"Automatic route-target configuration\n"                                                  \
	"Import and export\n"                                                                     \
	"Import\n"                                                                                \
	"Export\n"                                                                                \
	"Always add the automatic route-target, even when manual route-targets are configured\n"  \
	"Never add the automatic route-target\n"                                                  \
	"Add the automatic route-target only when no manual route-target is configured (default)\n"

DEFPY_YANG(bgp_evpn_vrf_auto_rt_yang, bgp_evpn_vrf_auto_rt_yang_cmd,
	   "auto-route-target <both|import|export>$type <add-always|add-never|add-if-no-manual|rfc8365-compatible>$mode",
	   AUTORT_HELP_STR
	   "Encode the automatic route-target as RFC 8365 compatible (set the VXLAN encapsulation bits in the local admin field)\n")
{
	return bgp_evpn_autort_cli(vty, true, false, type, mode);
}

DEFPY_YANG(no_bgp_evpn_vrf_auto_rt_yang, no_bgp_evpn_vrf_auto_rt_yang_cmd,
	   "no auto-route-target [<both|import|export>$type [<add-always|add-never|add-if-no-manual|rfc8365-compatible>$mode]]",
	   NO_STR
	   AUTORT_HELP_STR
	   "Encode the automatic route-target as RFC 8365 compatible (set the VXLAN encapsulation bits in the local admin field)\n")
{
	return bgp_evpn_autort_cli(vty, true, true, type, mode);
}

/* Deprecated: use "auto-route-target <both|import|export> add-always". */
DEFPY_ATTR(bgp_evpn_vrf_rt_auto_yang, bgp_evpn_vrf_rt_auto_yang_cmd,
	   "[no] route-target <both|import|export>$type auto",
	   NO_STR
	   "Route Target\n"
	   "import and export\n"
	   "import\n"
	   "export\n"
	   "Automatically derive route target\n",
	   CMD_ATTR_YANG | CMD_ATTR_DEPRECATED | CMD_ATTR_HIDDEN)
{
	if (strmatch(type, "import") || strmatch(type, "export") || strmatch(type, "both")) {
		vty_out(vty,
			"%% \"%sroute-target %s auto\" is deprecated, use \"%sauto-route-target %s add-always\"\n",
			no ? "no " : "", type, no ? "no " : "", type);
		return bgp_evpn_autort_cli(vty, true, !!no, type, "add-always");
	}

	vty_out(vty, "%% Invalid Route Target type\n");
	return CMD_WARNING_CONFIG_FAILED;
}

DEFPY_YANG_NOSH(bgp_evpn_vni_yang, bgp_evpn_vni_yang_cmd,
		"vni (1-16777215)$vni",
		"VXLAN Network Identifier\n"
		"VNI number\n")
{
	char af_xpath[XPATH_MAXLEN];
	char vni_rel[XPATH_MAXLEN + 256];
	char vni_abs[XPATH_MAXLEN + 256];
	int ret;

	/*
	 * Pure YANG enter (like bmp targets): create the VNI in the
	 * candidate and push its xpath. Do not require a live BGP/VPN
	 * object — under XFRR batch APPLY is deferred, so VTY context /
	 * nb_running lookups fail and nested "flooding …" would otherwise
	 * land on the parent EVPN node (overwriting global flooding).
	 */
	if (vty->xpath_index == 0) {
		vty_out(vty, "%% Missing BGP YANG context\n");
		return CMD_WARNING;
	}

	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	snprintfrr(vni_rel, sizeof(vni_rel), "%s/vni[vni='%" PRId64 "']", af_xpath, vni);

	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);
	nb_cli_enqueue_change(vty, vni_rel, NB_OP_CREATE, NULL);
	ret = nb_cli_apply_changes(vty, NULL);
	if (ret != CMD_SUCCESS)
		return ret;

	snprintfrr(vni_abs, sizeof(vni_abs),
		   "%s/global/afi-safis/afi-safi[afi-safi-name='frr-routing:l2vpn-evpn']/l2vpn-evpn/vni[vni='%" PRId64
		   "']",
		   VTY_CURR_XPATH, vni);
	VTY_PUSH_XPATH(BGP_EVPN_VNI_NODE, vni_abs);
	return CMD_SUCCESS;
}

DEFPY_YANG(no_bgp_evpn_vni_yang, no_bgp_evpn_vni_yang_cmd,
	   "no vni (1-16777215)$vni",
	   NO_STR
	   "VXLAN Network Identifier\n"
	   "VNI number\n")
{
	char af_xpath[XPATH_MAXLEN];
	char vni_rel[XPATH_MAXLEN + 256];

	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	snprintfrr(vni_rel, sizeof(vni_rel), "%s/vni[vni='%" PRId64 "']", af_xpath, vni);
	nb_cli_enqueue_change(vty, vni_rel, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG_NOSH(exit_vni_yang, exit_vni_yang_cmd, "exit-vni",
		"Exit from VNI mode\n")
{
	if (vty->node == BGP_EVPN_VNI_NODE) {
		vty->node = BGP_EVPN_NODE;
		if (vty->xpath_index > 0)
			vty->xpath_index--;
	}
	return CMD_SUCCESS;
}

DEFPY_YANG(bgp_evpn_vni_rd_yang, bgp_evpn_vni_rd_yang_cmd,
	   "[no] rd [ASN:NN_OR_IP-ADDRESS:NN$rd]",
	   NO_STR
	   EVPN_RT_DIST_HELP_STR
	   EVPN_ASN_IP_HELP_STR)
{
	struct bgp *bgp;
	struct bgpevpn *vpn;
	struct prefix_rd prd;
	const char *vni_key;
	vni_t vni = 0;

	if (!no) {
		if (!rd) {
			vty_out(vty, "%% Incomplete command\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		nb_cli_enqueue_change(vty, "./rd", NB_OP_MODIFY, rd);
		return nb_cli_apply_changes(vty, NULL);
	}

	bgp = VTY_GET_CONTEXT(bgp);
	vni_key = vty->xpath_index > 0 ? strstr(VTY_CURR_XPATH, "vni[vni='") : NULL;
	if (vni_key)
		vni = (vni_t)strtoul(vni_key + strlen("vni[vni='"), NULL, 10);
	vpn = (bgp && vni) ? bgp_evpn_lookup_vni(bgp, vni) : NULL;
	if (!vpn || !is_rd_configured(vpn)) {
		vty_out(vty, "%% RD is not configured for this VNI\n");
		return CMD_WARNING;
	}
	if (rd) {
		if (!str2prefix_rd(rd, &prd)) {
			vty_out(vty, "%% Malformed Route Distinguisher\n");
			return CMD_WARNING;
		}
		if (!bgp_evpn_rd_matches_existing(vpn, &prd)) {
			vty_out(vty,
				"%% RD specified does not match configuration for this VNI\n");
			return CMD_WARNING;
		}
	}
	nb_cli_enqueue_change(vty, "./rd", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_evpn_vni_rt_yang, bgp_evpn_vni_rt_yang_cmd,
	   "[no] route-target <both|import|export>$type RTLIST...",
	   NO_STR
	   "Route Target\n"
	   "import and export\n"
	   "import\n"
	   "export\n"
	   "Space separated route target list (A.B.C.D:MN|EF:OPQR|GHJK:MN|*:OPQR|*:MN)\n")
{
	bool do_import = false;
	bool do_export = false;
	int idx = 0;
	int i;

	if (strmatch(type, "import"))
		do_import = true;
	else if (strmatch(type, "export"))
		do_export = true;
	else if (strmatch(type, "both")) {
		do_import = true;
		do_export = true;
	} else {
		vty_out(vty, "%% Invalid Route Target type\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	argv_find(argv, argc, "RTLIST", &idx);
	if (!idx) {
		vty_out(vty, "%% Missing RTLIST\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	for (i = idx; i < argc; i++) {
		if (argv[i]->arg[0] == '*' && do_export) {
			vty_out(vty, "%% Wildcard '*' only applicable for import\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	{
		char abs_base[XPATH_MAXLEN];

		strlcpy(abs_base, VTY_CURR_XPATH, sizeof(abs_base));
		return bgp_evpn_rtlist_apply(vty, !!no, do_import, do_export, "VNI", ".", abs_base,
					     "import-route-target", "export-route-target", argv,
					     idx, argc);
	}
}

PREDECL_LIST(bgp_cli_vni_rt);

struct bgp_cli_vni_rt {
	char *rt;
	struct bgp_cli_vni_rt_item item;
};

DECLARE_LIST(bgp_cli_vni_rt, struct bgp_cli_vni_rt, item);

static void bgp_cli_vni_rt_clear(struct bgp_cli_vni_rt_head *head)
{
	struct bgp_cli_vni_rt *entry;

	while ((entry = bgp_cli_vni_rt_pop(head))) {
		XFREE(MTYPE_TMP, entry->rt);
		XFREE(MTYPE_TMP, entry);
	}
}

/* Remove every configured route-target of one direction from the L2VNI. */
DEFPY_YANG(no_bgp_evpn_vni_rt_without_val_yang, no_bgp_evpn_vni_rt_without_val_yang_cmd,
	   "no route-target <import|export>$type",
	   NO_STR
	   "Route Target\n"
	   "import\n"
	   "export\n")
{
	const struct lyd_node *vni_dnode, *child;
	const char *want = strmatch(type, "import") ? "import-route-target" : "export-route-target";
	struct bgp_cli_vni_rt_head rts;
	struct bgp_cli_vni_rt *entry;
	char leaf[XPATH_MAXLEN];

	/*
	 * Snapshot the values first so the walk of the candidate is finished
	 * before any change is queued.
	 */
	bgp_cli_vni_rt_init(&rts);
	vni_dnode = yang_dnode_get(vty->candidate_config->dnode, VTY_CURR_XPATH);
	if (vni_dnode) {
		LY_LIST_FOR (lyd_child(vni_dnode), child) {
			if (!strmatch(child->schema->name, want))
				continue;
			entry = XCALLOC(MTYPE_TMP, sizeof(*entry));
			entry->rt = XSTRDUP(MTYPE_TMP, yang_dnode_get_string(child, NULL));
			bgp_cli_vni_rt_add_tail(&rts, entry);
		}
	}

	if (!bgp_cli_vni_rt_count(&rts)) {
		bgp_cli_vni_rt_fini(&rts);
		vty_out(vty, "%% %s RT is not configured for this VNI\n",
			strmatch(type, "import") ? "Import" : "Export");
		return CMD_WARNING_CONFIG_FAILED;
	}

	frr_each (bgp_cli_vni_rt, &rts, entry) {
		snprintfrr(leaf, sizeof(leaf), "./%s[.='%s']", want, entry->rt);
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	}
	bgp_cli_vni_rt_clear(&rts);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_evpn_vni_auto_rt_yang, bgp_evpn_vni_auto_rt_yang_cmd,
	   "auto-route-target <both|import|export>$type <add-always|add-never|add-if-no-manual>$mode",
	   AUTORT_HELP_STR)
{
	return bgp_evpn_autort_cli(vty, false, false, type, mode);
}

DEFPY_YANG(no_bgp_evpn_vni_auto_rt_yang, no_bgp_evpn_vni_auto_rt_yang_cmd,
	   "no auto-route-target [<both|import|export>$type [<add-always|add-never|add-if-no-manual>$mode]]",
	   NO_STR
	   AUTORT_HELP_STR)
{
	return bgp_evpn_autort_cli(vty, false, true, type, mode);
}

DEFPY_YANG(bgp_evpn_vni_advertise_default_gw_yang,
	   bgp_evpn_vni_advertise_default_gw_yang_cmd,
	   "[no] advertise-default-gw",
	   NO_STR
	   "Advertise default g/w mac-ip routes in EVPN for a VNI\n")
{
	nb_cli_enqueue_change(vty, "./advertise-default-gateway", NB_OP_MODIFY,
			      no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_evpn_vni_advertise_svi_ip_yang,
	   bgp_evpn_vni_advertise_svi_ip_yang_cmd,
	   "[no] advertise-svi-ip",
	   NO_STR
	   "Advertise svi mac-ip routes in EVPN for a VNI\n")
{
	nb_cli_enqueue_change(vty, "./advertise-svi-ip", NB_OP_MODIFY, no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_evpn_vni_advertise_subnet_yang,
	   bgp_evpn_vni_advertise_subnet_yang_cmd,
	   "[no] advertise-subnet",
	   NO_STR
	   "Advertise the subnet corresponding to VNI\n")
{
	nb_cli_enqueue_change(vty, "./advertise-subnet", NB_OP_MODIFY, no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_evpn_vni_flooding_yang, bgp_evpn_vni_flooding_yang_cmd,
	   "[no] flooding <disable$disable|head-end-replication$her>",
	   NO_STR
	   "Specify handling for BUM packets\n"
	   "Do not flood any BUM packets\n"
	   "Flood BUM packets using head-end replication\n")
{
	const char *val;

	if (no)
		val = "inherit-global";
	else if (disable)
		val = "disable";
	else if (her)
		val = "head-end-replication";
	else
		return CMD_WARNING_CONFIG_FAILED;

	nb_cli_enqueue_change(vty, "./flooding", NB_OP_MODIFY, val);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_imexport_vpn_yang, bgp_imexport_vpn_yang_cmd,
	   "[no] <import|export>$direction_str vpn",
	   NO_STR
	   "Import routes to this address-family\n"
	   "Export routes from this address-family\n"
	   "to/from default instance VPN RIB\n")
{
	char af_xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	const char *leafname;

	if (!strcmp(direction_str, "import"))
		leafname = "import-vpn";
	else if (!strcmp(direction_str, "export"))
		leafname = "export-vpn";
	else {
		vty_out(vty, "%% unknown direction %s\n", direction_str);
		return CMD_WARNING_CONFIG_FAILED;
	}

	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/vpn-config/%s", af_xpath, leafname);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(af_route_map_vpn_yang, af_route_map_vpn_yang_cmd,
	   "[no] route-map vpn <import|export>$direction_str [RMAP$rmap_str]",
	   NO_STR
	   "Specify route map\n"
	   "Between current address-family and vpn\n"
	   "For routes leaked from vpn to current address-family\n"
	   "For routes leaked from current address-family to vpn\n"
	   "name of route-map\n")
{
	char af_xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	const char *leafname;

	if (!strcmp(direction_str, "import"))
		leafname = "rmap-import";
	else if (!strcmp(direction_str, "export"))
		leafname = "rmap-export";
	else {
		vty_out(vty, "%% direction parse error\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/vpn-config/%s", af_xpath, leafname);
	if (no)
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	else {
		if (!rmap_str)
			return CMD_WARNING_CONFIG_FAILED;
		if (!strcmp(direction_str, "import")) {
			char other[XPATH_MAXLEN + 256];

			snprintfrr(other, sizeof(other), "%s/vpn-config/vrf-rmap-import", af_xpath);
			nb_cli_enqueue_change(vty, other, NB_OP_DESTROY, NULL);
		}
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, rmap_str);
	}
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(af_import_vrf_route_map_yang, af_import_vrf_route_map_yang_cmd,
	   "[no] import vrf route-map [RMAP$rmap_str]",
	   NO_STR
	   "Import routes from another VRF\n"
	   "Vrf routes being filtered\n"
	   "Specify route map\n"
	   "name of route-map\n")
{
	char af_xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	char other[XPATH_MAXLEN + 256];

	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/vpn-config/vrf-rmap-import", af_xpath);
	if (no)
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	else {
		if (!rmap_str)
			return CMD_WARNING_CONFIG_FAILED;
		snprintfrr(other, sizeof(other), "%s/vpn-config/rmap-import", af_xpath);
		nb_cli_enqueue_change(vty, other, NB_OP_DESTROY, NULL);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, rmap_str);
	}
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(af_rd_vpn_export_yang, af_rd_vpn_export_yang_cmd,
	   "[no] rd vpn export [ASN:NN_OR_IP-ADDRESS:NN$rd_str]",
	   NO_STR
	   "Specify route distinguisher\n"
	   "Between current address-family and vpn\n"
	   "For routes leaked from current address-family to vpn\n"
	   "Route Distinguisher (<as-number>:<number> | <ip-address>:<number>)\n")
{
	char af_xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];

	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/vpn-config/rd", af_xpath);
	if (no)
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	else {
		if (!rd_str)
			return CMD_WARNING_CONFIG_FAILED;
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, rd_str);
	}
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(af_label_vpn_export_yang, af_label_vpn_export_yang_cmd,
	   "[no] label vpn export [<(0-1048575)$label_val|auto$label_auto>]",
	   NO_STR
	   "label value for VRF\n"
	   "Between current address-family and vpn\n"
	   "For routes leaked from current address-family to vpn\n"
	   "Label Value <0-1048575>\n"
	   "Automatically assign a label\n")
{
	char af_xpath[XPATH_MAXLEN];
	char label_xpath[XPATH_MAXLEN + 256];
	char auto_xpath[XPATH_MAXLEN + 256];
	char buf[16];
	//struct bgp *bgp;

	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);
	snprintfrr(label_xpath, sizeof(label_xpath), "%s/vpn-config/label", af_xpath);
	snprintfrr(auto_xpath, sizeof(auto_xpath), "%s/vpn-config/label-auto", af_xpath);

	if (no) {
		if (label_auto) {
			//		if (!CHECK_FLAG(bgp->vpn_policy[afi].flags,
			//				BGP_VPN_POLICY_TOVPN_LABEL_AUTO))
			//			return CMD_WARNING_CONFIG_FAILED;
			nb_cli_enqueue_change(vty, auto_xpath, NB_OP_DESTROY, NULL);
		} else if (label_val_str) {
			//		if (CHECK_FLAG(bgp->vpn_policy[afi].flags,
			//			       BGP_VPN_POLICY_TOVPN_LABEL_AUTO) ||
			//		    (mpls_label_t)label_val !=
			//			    bgp->vpn_policy[afi].tovpn_label)
			//			return CMD_WARNING_CONFIG_FAILED;
			nb_cli_enqueue_change(vty, label_xpath, NB_OP_DESTROY, NULL);
		} else {
			nb_cli_enqueue_change(vty, label_xpath, NB_OP_DESTROY, NULL);
			nb_cli_enqueue_change(vty, auto_xpath, NB_OP_DESTROY, NULL);
		}
	} else if (label_auto) {
		nb_cli_enqueue_change(vty, label_xpath, NB_OP_DESTROY, NULL);
		nb_cli_enqueue_change(vty, auto_xpath, NB_OP_MODIFY, "true");
	} else if (label_val_str) {
		snprintfrr(buf, sizeof(buf), "%" PRId64, label_val);
		nb_cli_enqueue_change(vty, auto_xpath, NB_OP_DESTROY, NULL);
		nb_cli_enqueue_change(vty, label_xpath, NB_OP_MODIFY, buf);
	} else
		return CMD_WARNING_CONFIG_FAILED;

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(af_label_vpn_alloc_mode_yang, af_label_vpn_alloc_mode_yang_cmd,
	   "[no$no] label vpn export allocation-mode <per-vrf$label_per_vrf|per-nexthop$label_per_nh>",
	   NO_STR
	   "label value for VRF\n"
	   "Between current address-family and vpn\n"
	   "For routes leaked from current address-family to vpn\n"
	   "Label allocation mode\n"
	   "Allocate one label for all BGP updates of the VRF\n"
	   "Allocate a label per connected next-hop in the VRF\n")
{
	char af_xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	//bool old_per_nexthop;

	//old_per_nexthop = !!CHECK_FLAG(bgp->vpn_policy[afi].flags,
	//			      BGP_VPN_POLICY_TOVPN_LABEL_PER_NEXTHOP);

	if (no) {
		//if (!old_per_nexthop && label_per_nh)
		//	return CMD_ERR_NO_MATCH;
		//if (old_per_nexthop && label_per_vrf)
		//	return CMD_ERR_NO_MATCH;
	}

	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/vpn-config/export-allocation-mode", af_xpath);
	if (no)
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY,
				      label_per_nh ? "per-nexthop" : "per-vrf");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(af_nexthop_vpn_export_yang, af_nexthop_vpn_export_yang_cmd,
	   "[no] nexthop vpn export [<A.B.C.D|X:X::X:X>$nexthop]",
	   NO_STR
	   "Specify next hop to use for VRF advertised prefixes\n"
	   "Between current address-family and vpn\n"
	   "For routes leaked from current address-family to vpn\n"
	   "IPv4 prefix\n"
	   "IPv6 prefix\n")
{
	char af_xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];

	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/vpn-config/nexthop", af_xpath);
	if (no)
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	else {
		if (!nexthop_str)
			return CMD_WARNING_CONFIG_FAILED;
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, nexthop_str);
	}
	return nb_cli_apply_changes(vty, NULL);
}

static void bgp_cli_vpn_rt_clear(struct vty *vty, const char *af_xpath, const char *list_name)
{
	char check[XPATH_MAXLEN + 256];
	char leaf[XPATH_MAXLEN + 256];
	const struct lyd_node *dnode, *parent, *child, *next;

	snprintfrr(check, sizeof(check), "%s%s/vpn-config/%s", VTY_CURR_XPATH, af_xpath + 1,
		   list_name);
	dnode = yang_dnode_get(vty->candidate_config->dnode, check);
	if (!dnode)
		return;

	parent = lyd_parent(dnode);
	for (child = lyd_child(parent); child; child = next) {
		next = child->next;
		if (child->schema->nodetype != LYS_LEAFLIST)
			continue;
		if (!strmatch(child->schema->name, list_name))
			continue;
		snprintfrr(leaf, sizeof(leaf), "%s/vpn-config/%s[.='%s']", af_xpath, list_name,
			   yang_dnode_get_string(child, NULL));
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	}
}

static void bgp_cli_vpn_rt_set(struct vty *vty, const char *af_xpath, const char *list_name,
			       int argc, struct cmd_token **argv)
{
	char leaf[XPATH_MAXLEN + 256];

	bgp_cli_vpn_rt_clear(vty, af_xpath, list_name);
	for (; argc; --argc, ++argv) {
		snprintfrr(leaf, sizeof(leaf), "%s/vpn-config/%s[.='%s']", af_xpath, list_name,
			   argv[0]->arg);
		nb_cli_enqueue_change(vty, leaf, NB_OP_CREATE, NULL);
	}
}

DEFPY_YANG(af_rt_vpn_yang, af_rt_vpn_yang_cmd,
	   "[no] <rt|route-target> vpn <import|export|both>$direction_str RTLIST...",
	   NO_STR
	   "Specify route target list\n"
	   "Specify route target list\n"
	   "Between current address-family and vpn\n"
	   "For routes leaked from vpn to current address-family: match any\n"
	   "For routes leaked from current address-family to vpn: set\n"
	   "both import: match any and export: set\n"
	   "Space separated route target list (A.B.C.D:MN|EF:OPQR|GHJK:MN)\n")
{
	char af_xpath[XPATH_MAXLEN];
	int idx = 0;
	bool do_import = false;
	bool do_export = false;

	if (!strcmp(direction_str, "import"))
		do_import = true;
	else if (!strcmp(direction_str, "export"))
		do_export = true;
	else if (!strcmp(direction_str, "both")) {
		do_import = true;
		do_export = true;
	} else {
		vty_out(vty, "%% direction parse error\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);

	argv_find(argv, argc, "RTLIST", &idx);
	if (no) {
		if (do_import)
			bgp_cli_vpn_rt_clear(vty, af_xpath, "import-rt-list");
		if (do_export)
			bgp_cli_vpn_rt_clear(vty, af_xpath, "export-rt-list");
	} else {
		if (!idx) {
			vty_out(vty, "%% Missing RTLIST\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		if (do_import)
			bgp_cli_vpn_rt_set(vty, af_xpath, "import-rt-list", argc - idx, argv + idx);
		if (do_export)
			bgp_cli_vpn_rt_set(vty, af_xpath, "export-rt-list", argc - idx, argv + idx);
	}
	return nb_cli_apply_changes(vty, NULL);
}

ALIAS_ATTR(af_rt_vpn_yang, af_no_rt_vpn_yang_cmd,
	   "no <rt|route-target> vpn <import|export|both>$direction_str",
	   NO_STR
	   "Specify route target list\n"
	   "Specify route target list\n"
	   "Between current address-family and vpn\n"
	   "For routes leaked from vpn to current address-family\n"
	   "For routes leaked from current address-family to vpn\n"
	   "both import and export\n",
	   CMD_ATTR_YANG);

DEFPY_YANG(bgp_import_vrf_yang, bgp_import_vrf_yang_cmd,
	   "[no] import vrf VIEWVRFNAME$import_name",
	   NO_STR
	   "Import routes from another VRF\n"
	   "VRF to import from\n"
	   "The name of the VRF\n")
{
	char af_xpath[XPATH_MAXLEN];
	char list_xpath[XPATH_MAXLEN + 256];

	if (!import_name) {
		vty_out(vty, "%% Missing import name\n");
		return CMD_WARNING;
	}
	if (strmatch(import_name, "route-map")) {
		vty_out(vty, "%% Must include route-map name\n");
		return CMD_WARNING;
	}

	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);
	snprintfrr(list_xpath, sizeof(list_xpath), "%s/vpn-config/import-vrf-list[vrf='%s']",
		   af_xpath, import_name);
	nb_cli_enqueue_change(vty, list_xpath, no ? NB_OP_DESTROY : NB_OP_CREATE, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bgp_retain_route_target_yang, bgp_retain_route_target_yang_cmd,
	   "[no] bgp retain route-target all",
	   NO_STR BGP_STR
	   "Retain BGP updates\n"
	   "Retain BGP updates based on route-target values\n"
	   "Retain all BGP updates\n")
{
	char af_xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];

	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/retain-route-target-all", af_xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(vpn_network_yang, vpn_network_yang_cmd,
	   "[no] network <A.B.C.D/M$prefix4|X:X::X:X/M$prefix6> rd ASN:NN_OR_IP-ADDRESS:NN$rd <tag|label> (0-1048575)$label [route-map RMAP_NAME$map_name]",
	   NO_STR
	   "Specify a network to announce via BGP\n"
	   "IPv4 prefix\n"
	   "IPv6 prefix\n"
	   "Specify Route Distinguisher\n"
	   "VPN Route Distinguisher\n"
	   "VPN NLRI label (tag)\n"
	   "VPN NLRI label (tag)\n"
	   "Label value\n"
	   "Route map\n"
	   "Route map name\n")
{
	char af_xpath[XPATH_MAXLEN];
	char rd_xpath[XPATH_MAXLEN + 256];
	char pfx_xpath[XPATH_MAXLEN + 512];
	char leaf[XPATH_MAXLEN + 768];
	char buf[16];
	const char *pfx;

	pfx = prefix4_str ? prefix4_str : prefix6_str;
	if (!pfx)
		return CMD_WARNING_CONFIG_FAILED;

	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);
	snprintfrr(rd_xpath, sizeof(rd_xpath), "%s/network-config[rd='%s']", af_xpath, rd);
	snprintfrr(pfx_xpath, sizeof(pfx_xpath), "%s/prefix-list[prefix='%s']", rd_xpath, pfx);

	if (no) {
		nb_cli_enqueue_change(vty, pfx_xpath, NB_OP_DESTROY, NULL);
		return nb_cli_apply_changes(vty, NULL);
	}

	nb_cli_enqueue_change(vty, rd_xpath, NB_OP_CREATE, NULL);
	nb_cli_enqueue_change(vty, pfx_xpath, NB_OP_CREATE, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/label-index", pfx_xpath);
	snprintfrr(buf, sizeof(buf), "%" PRId64, label);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, buf);
	snprintfrr(leaf, sizeof(leaf), "%s/rmap-policy-export", pfx_xpath);
	if (map_name)
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, map_name);
	else
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

/*
 * BMP
 */
#ifndef BMP_STR
#define BMP_STR "BGP Monitoring Protocol\n"
#endif

DEFPY_YANG(bmp_mirror_limit_yang, bmp_mirror_limit_yang_cmd,
	   "[no] bmp mirror buffer-limit [(0-4294967294)$limit]",
	   NO_STR
	   BMP_STR
	   "Route Mirroring settings\n"
	   "Configure maximum memory used for buffered mirroring messages\n"
	   "Limit in bytes\n")
{
	char leaf[XPATH_MAXLEN];
	char buf[16];

	snprintfrr(leaf, sizeof(leaf), "./global/bmp-config/mirror-buffer-limit");
	if (no)
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	else {
		if (!limit_str)
			return CMD_WARNING_CONFIG_FAILED;
		snprintfrr(buf, sizeof(buf), "%" PRId64, limit);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, buf);
	}
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG_NOSH(bmp_targets_yang, bmp_targets_yang_cmd,
		"bmp targets BMPTARGETS$name",
		BMP_STR
		"Create BMP target group\n"
		"Name of the BMP target group\n")
{
	char abs[XPATH_MAXLEN + 256];
	int ret;

	/*
	 * Pure YANG enter: create the target-list entry in the candidate and
	 * push its xpath.  Do not call into the BMP module or consult BGP
	 * operational objects — nb_cli_apply_changes() already runs
	 * northbound validation/apply (or candidate edit in transactional
	 * mode).  Matching bfdd/isisd/ripd DEFPY_YANG_NOSH enter commands.
	 */
	if (vty->xpath_index == 0) {
		vty_out(vty, "%% Missing BGP YANG context\n");
		return CMD_WARNING;
	}

	nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, NULL);
	ret = nb_cli_apply_changes(vty, "./global/bmp-config/target-list[target-name='%s']", name);
	if (ret != CMD_SUCCESS)
		return ret;

	snprintfrr(abs, sizeof(abs), "%s/global/bmp-config/target-list[target-name='%s']",
		   VTY_CURR_XPATH, name);
	VTY_PUSH_XPATH(BMP_NODE, abs);
	return CMD_SUCCESS;
}

DEFPY_YANG(no_bmp_targets_yang, no_bmp_targets_yang_cmd,
	   "no bmp targets BMPTARGETS$name",
	   NO_STR
	   BMP_STR
	   "Delete BMP target group\n"
	   "Name of the BMP target group\n")
{
	char abs[XPATH_MAXLEN + 256];

	if (vty->xpath_index == 0) {
		vty_out(vty, "%% Missing BGP YANG context\n");
		return CMD_WARNING;
	}

	/* Existence from candidate YANG state, not operational bmp_targets. */
	snprintfrr(abs, sizeof(abs), "%s/global/bmp-config/target-list[target-name='%s']",
		   VTY_CURR_XPATH, name);
	if (!yang_dnode_exists(vty->candidate_config->dnode, abs)) {
		vty_out(vty, "%% BMP target group not found\n");
		return CMD_WARNING;
	}

	nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, "./global/bmp-config/target-list[target-name='%s']", name);
}

DEFPY_YANG(bmp_mirror_yang, bmp_mirror_yang_cmd, "[no] bmp mirror",
	   NO_STR BMP_STR "Send BMP route mirroring messages\n")
{
	nb_cli_enqueue_change(vty, "./mirror", NB_OP_MODIFY, no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bmp_stats_yang, bmp_stats_yang_cmd,
	   "[no] bmp stats [interval (100-86400000)$interval]",
	   NO_STR
	   BMP_STR
	   "Send BMP statistics messages\n"
	   "Specify BMP stats interval\n"
	   "Interval (milliseconds) to send BMP Stats in\n")
{
	char buf[16];

	if (no) {
		nb_cli_enqueue_change(vty, "./stats-time", NB_OP_DESTROY, NULL);
		return nb_cli_apply_changes(vty, NULL);
	}

	if (interval_str)
		snprintfrr(buf, sizeof(buf), "%" PRId64, interval);
	else
		/* Classic default (BMP_STAT_DEFAULT_TIMER); avoid BMP module. */
		snprintfrr(buf, sizeof(buf), "%u", 60000U);
	nb_cli_enqueue_change(vty, "./stats-time", NB_OP_MODIFY, buf);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bmp_stats_experimental_yang, bmp_stats_experimental_yang_cmd,
	   "[no] bmp stats send-experimental",
	   NO_STR
	   BMP_STR
	   "Send BMP statistics messages\n"
	   "Send experimental BMP stats [65531-65534]\n")
{
	nb_cli_enqueue_change(vty, "./stats-send-experimental", NB_OP_MODIFY,
			      no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bmp_acl_yang, bmp_acl_yang_cmd,
	   "[no] <ip|ipv6>$af access-list ACCESSLIST_NAME$access_list",
	   NO_STR
	   IP_STR
	   IPV6_STR
	   "Access list to restrict BMP sessions\n"
	   "Access list name\n")
{
	const char *leaf;

	leaf = strmatch(af, "ipv6") ? "./ipv6-access-list" : "./ipv4-access-list";
	if (no)
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, access_list);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bmp_initiation_yang, bmp_initiation_yang_cmd,
	   "[no] bmp initiation <sysDescr|sysName>$info LINE...",
	   NO_STR
	   BMP_STR
	   "BMP Initiation message\n"
	   "System description, by default the FRR version\n"
	   "System name, by default the hostname\n"
	   "String to send\n")
{
	const char *leaf = strmatch(info, "sysDescr") ? "./initiation-sysdescr"
						      : "./initiation-sysname";
	char *str;
	int idx = 0;

	if (no) {
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
		return nb_cli_apply_changes(vty, NULL);
	}

	if (!argv_find(argv, argc, "LINE", &idx)) {
		vty_out(vty, "%% Missing string to send\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	str = argv_concat(argv, argc, idx);
	if (strlen(str) > 255) {
		vty_out(vty, "%% %s length should be at most 255 chars\n", info);
		XFREE(MTYPE_TMP, str);
		return CMD_WARNING_CONFIG_FAILED;
	}
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, str);
	idx = nb_cli_apply_changes(vty, NULL);
	XFREE(MTYPE_TMP, str);
	return idx;
}

DEFPY_YANG(no_bmp_initiation_yang, no_bmp_initiation_yang_cmd,
	   "no bmp initiation <sysDescr|sysName>$info",
	   NO_STR
	   BMP_STR
	   "BMP Initiation message\n"
	   "System description, by default the FRR version\n"
	   "System name, by default the hostname\n")
{
	nb_cli_enqueue_change(vty,
			      strmatch(info, "sysDescr") ? "./initiation-sysdescr"
							 : "./initiation-sysname",
			      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bmp_listener_yang, bmp_listener_yang_cmd,
	   "[no] bmp listener <A.B.C.D|X:X::X:X>$addr port (1-65535)$port",
	   NO_STR
	   BMP_STR
	   "Listen for inbound BMP connections\n"
	   "IPv4 address to listen on\n"
	   "IPv6 address to listen on\n"
	   "TCP Port number\n"
	   "TCP Port number\n")
{
	char xpath[XPATH_MAXLEN];

	snprintfrr(xpath, sizeof(xpath),
		   "./incoming-session/session-list[address='%s'][tcp-port='%" PRId64 "']",
		   addr_str, port);
	nb_cli_enqueue_change(vty, xpath, no ? NB_OP_DESTROY : NB_OP_CREATE, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bmp_connect_yang, bmp_connect_yang_cmd,
	   "[no] bmp connect HOSTNAME$host port (1-65535)$port {min-retry (100-86400000)$min_retry|max-retry (100-86400000)$max_retry} [source-interface WORD$srcif]",
	   NO_STR
	   BMP_STR
	   "Actively establish connection to monitoring station\n"
	   "Monitoring station hostname or address\n"
	   "TCP port\n"
	   "TCP port\n"
	   "Minimum connection retry interval\n"
	   "Minimum connection retry interval (milliseconds)\n"
	   "Maximum connection retry interval\n"
	   "Maximum connection retry interval (milliseconds)\n"
	   "Source interface to use\n"
	   "Interface name\n")
{
	char sess[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	char min_buf[16], max_buf[16];
	int64_t min_ms = min_retry_str ? min_retry : 30000;
	int64_t max_ms = max_retry_str ? max_retry : 720000;

	snprintfrr(sess, sizeof(sess),
		   "./outgoing-session/session-list[hostname='%s'][tcp-port='%" PRId64 "']", host,
		   port);

	if (no) {
		nb_cli_enqueue_change(vty, sess, NB_OP_DESTROY, NULL);
		return nb_cli_apply_changes(vty, NULL);
	}

	nb_cli_enqueue_change(vty, sess, NB_OP_CREATE, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/min-retry-time", sess);
	/* YANG defaults: 30000 / 720000 — avoid BMP module macros in CLI. */
	snprintfrr(min_buf, sizeof(min_buf), "%" PRId64, min_ms);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, min_buf);
	snprintfrr(leaf, sizeof(leaf), "%s/max-retry-time", sess);
	snprintfrr(max_buf, sizeof(max_buf), "%" PRId64, max_ms);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, max_buf);
	snprintfrr(leaf, sizeof(leaf), "%s/source-interface", sess);
	if (srcif)
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, srcif);
	else
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bmp_import_vrf_yang, bmp_import_vrf_yang_cmd,
	   "[no] bmp import-vrf-view VRFNAME$vrfname",
	   NO_STR
	   BMP_STR
	   "Import BMP information from another VRF\n"
	   "Specify the VRF or view instance name\n")
{
	char leaf[XPATH_MAXLEN];

	snprintfrr(leaf, sizeof(leaf), "./import-vrf[.='%s']", vrfname);
	nb_cli_enqueue_change(vty, leaf, no ? NB_OP_DESTROY : NB_OP_CREATE, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(bmp_monitor_yang, bmp_monitor_yang_cmd,
	   "[no] bmp monitor <ipv4|ipv6|l2vpn>$afi_str <unicast|multicast|evpn|vpn>$safi_str <pre-policy|post-policy|loc-rib>$policy",
	   NO_STR
	   BMP_STR
	   "Send BMP route monitoring messages\n"
	   BGP_AF_STR BGP_AF_STR BGP_AF_STR
	   BGP_AF_STR BGP_AF_STR BGP_AF_STR BGP_AF_STR
	   "Send state before policy and filter processing\n"
	   "Send state with policy and filters applied\n"
	   "Send state after decision process is applied\n")
{
	char af_xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	const char *ident;
	afi_t afi = AFI_IP;
	safi_t safi = SAFI_UNICAST;

	if (strmatch(afi_str, "ipv6"))
		afi = AFI_IP6;
	else if (strmatch(afi_str, "l2vpn"))
		afi = AFI_L2VPN;

	if (strmatch(safi_str, "multicast"))
		safi = SAFI_MULTICAST;
	else if (strmatch(safi_str, "vpn"))
		safi = SAFI_MPLS_VPN;
	else if (strmatch(safi_str, "evpn"))
		safi = SAFI_EVPN;

	ident = yang_afi_safi_value2identity(afi, safi);
	if (!ident) {
		vty_out(vty, "%% Unsupported BMP monitor AFI/SAFI\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* ident is "frr-routing:<af>"; BMP common-config lives under <af>/. */
	{
		const char *af_cont = strchr(ident, ':');

		af_cont = af_cont ? af_cont + 1 : ident;
		snprintfrr(af_xpath, sizeof(af_xpath),
			   "./afi-safis/afi-safi[afi-safi-name='%s']/%s", ident, af_cont);
	}
	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/common-config/%s", af_xpath, policy);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(af_routetarget_redirect_yang, af_routetarget_redirect_yang_cmd,
	   "[no] <rt|route-target|route-target6|rt6>$rt_kw redirect import RTLIST...",
	   NO_STR
	   "Specify route target list\n"
	   "Specify route target list\n"
	   "Specify route target list\n"
	   "Specify route target list\n"
	   "Flow-spec redirect type route target\n"
	   "Import routes to this address-family\n"
	   "Space separated route target list (A.B.C.D:MN|EF:OPQR|GHJK:MN|IPV6:MN)\n")
{
	char af_xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	char ipv6_leaf[XPATH_MAXLEN + 256];
	char *rts = NULL;
	int idx = 0;
	int ret;
	bool ipv6 = false;

	if (!strcmp(rt_kw, "rt6") || !strcmp(rt_kw, "route-target6"))
		ipv6 = true;

	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/vpn-config/redirect-rt", af_xpath);
	snprintfrr(ipv6_leaf, sizeof(ipv6_leaf), "%s/vpn-config/redirect-rt-ipv6", af_xpath);

	argv_find(argv, argc, "RTLIST", &idx);
	if (no) {
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
		nb_cli_enqueue_change(vty, ipv6_leaf, NB_OP_DESTROY, NULL);
	} else {
		if (!idx) {
			vty_out(vty, "%% Missing RTLIST\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		rts = argv_concat(argv, argc, idx);
		nb_cli_enqueue_change(vty, ipv6_leaf, NB_OP_MODIFY, ipv6 ? "true" : "false");
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, rts);
	}
	/* rts is the stored value pointer; free it only after apply copies it. */
	ret = nb_cli_apply_changes(vty, NULL);
	XFREE(MTYPE_TMP, rts);
	return ret;
}

static void bgp_cli_sid_export_clear(struct vty *vty, const char *af_xpath)
{
	char leaf[XPATH_MAXLEN + 256];

	snprintfrr(leaf, sizeof(leaf), "%s/sid-export/sid-index", af_xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/sid-export/sid-auto", af_xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/sid-export/sid-explicit", af_xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/sid-export/behavior-dt46", af_xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/sid-export/route-map", af_xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
}

DEFPY_YANG(sid_export_yang, sid_export_yang_cmd,
	   "[no] sid export [<(1-1048575)$sid_idx|auto$sid_auto|explicit$sid_explicit X:X::X:X$sid_value> [behavior dt46$behavior_dt46] [route-map RMAP$rmap_str]]",
	   NO_STR
	   "Sid value for VRF\n"
	   "Encapsulation SRv6 over default vrf\n"
	   "Sid allocation index\n"
	   "Automatically assign a label\n"
	   "Explicitly assign a sid value\n"
	   "Sid value\n"
	   "Specify SRv6 SID behavior\n"
	   "Allocate a DT46 SID\n"
	   "Specify route-map name\n"
	   "Name of route-map\n")
{
	char af_xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	char buf[16];

	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);

	if (no) {
		bgp_cli_sid_export_clear(vty, af_xpath);
		return nb_cli_apply_changes(vty, NULL);
	}

	if (!sid_idx_str && !sid_auto && !sid_explicit)
		return CMD_WARNING_CONFIG_FAILED;

	/*
	 * Choice: destroy only sibling allocation leaves so a same-mode
	 * re-apply (e.g. route-map update) does not tear down the SID.
	 */
	if (!sid_auto) {
		snprintfrr(leaf, sizeof(leaf), "%s/sid-export/sid-auto", af_xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	}
	if (!sid_explicit) {
		snprintfrr(leaf, sizeof(leaf), "%s/sid-export/sid-explicit", af_xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	}
	if (!sid_idx_str) {
		snprintfrr(leaf, sizeof(leaf), "%s/sid-export/sid-index", af_xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	}

	if (sid_auto) {
		snprintfrr(leaf, sizeof(leaf), "%s/sid-export/sid-auto", af_xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_CREATE, NULL);
	} else if (sid_explicit) {
		snprintfrr(leaf, sizeof(leaf), "%s/sid-export/sid-explicit", af_xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, sid_value_str);
	} else {
		snprintfrr(buf, sizeof(buf), "%" PRId64, sid_idx);
		snprintfrr(leaf, sizeof(leaf), "%s/sid-export/sid-index", af_xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, buf);
	}

	snprintfrr(leaf, sizeof(leaf), "%s/sid-export/behavior-dt46", af_xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, behavior_dt46 ? "true" : "false");

	/* Classic: omitting route-map leaves any existing map unchanged. */
	if (rmap_str) {
		snprintfrr(leaf, sizeof(leaf), "%s/sid-export/route-map", af_xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, rmap_str);
	}

	return nb_cli_apply_changes(vty, NULL);
}

static void bgp_cli_sid_vpn_export_clear(struct vty *vty, const char *af_xpath)
{
	char leaf[XPATH_MAXLEN + 256];

	snprintfrr(leaf, sizeof(leaf), "%s/vpn-config/sid-vpn-export/sid-index", af_xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/vpn-config/sid-vpn-export/sid-auto", af_xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/vpn-config/sid-vpn-export/sid-explicit", af_xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
}

DEFPY_YANG(af_sid_vpn_export_yang, af_sid_vpn_export_yang_cmd,
	   "[no] sid vpn export [<(1-4294967295)$sid_idx|auto$sid_auto|explicit$sid_explicit X:X::X:X$sid_value>]",
	   NO_STR
	   "sid value for VRF\n"
	   "Between current address-family and vpn\n"
	   "For routes leaked from current address-family to vpn\n"
	   "Sid allocation index\n"
	   "Automatically assign a label\n"
	   "Explicitly assign a sid value\n"
	   "Sid value\n")
{
	char af_xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	char buf[16];

	bgp_cli_global_af_xpath(vty, af_xpath, sizeof(af_xpath));
	nb_cli_enqueue_change(vty, af_xpath, NB_OP_CREATE, NULL);

	if (no) {
		bgp_cli_sid_vpn_export_clear(vty, af_xpath);
		return nb_cli_apply_changes(vty, NULL);
	}

	if (!sid_idx_str && !sid_auto && !sid_explicit)
		return CMD_WARNING_CONFIG_FAILED;

	if (!sid_auto) {
		snprintfrr(leaf, sizeof(leaf), "%s/vpn-config/sid-vpn-export/sid-auto", af_xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	}
	if (!sid_explicit) {
		snprintfrr(leaf, sizeof(leaf), "%s/vpn-config/sid-vpn-export/sid-explicit",
			   af_xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	}
	if (!sid_idx_str) {
		snprintfrr(leaf, sizeof(leaf), "%s/vpn-config/sid-vpn-export/sid-index", af_xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	}

	if (sid_auto) {
		snprintfrr(leaf, sizeof(leaf), "%s/vpn-config/sid-vpn-export/sid-auto", af_xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_CREATE, NULL);
	} else if (sid_explicit) {
		snprintfrr(leaf, sizeof(leaf), "%s/vpn-config/sid-vpn-export/sid-explicit",
			   af_xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, sid_value_str);
	} else {
		snprintfrr(buf, sizeof(buf), "%" PRId64, sid_idx);
		snprintfrr(leaf, sizeof(leaf), "%s/vpn-config/sid-vpn-export/sid-index", af_xpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, buf);
	}

	return nb_cli_apply_changes(vty, NULL);
}


static int bgp_cli_peer_af_xpath(struct vty *vty, const char *neighbor, char *xpath,
				 size_t xpath_len, bool *is_pg)
{
	char base[XPATH_MAXLEN];
	char check[XPATH_MAXLEN + 256];
	const char *afi_safi;
	int ret;

	ret = bgp_cli_neighbor_base_xpath(vty, neighbor, base, sizeof(base), is_pg);
	if (ret != 0)
		return ret;

	/*
	 * Classic AF neighbor cmds require an existing peer (remote-as or
	 * peer-group first). Creating afi-safi under a missing neighbor would
	 * auto-create the list entry.
	 */
	snprintfrr(check, sizeof(check), "%s/%s", VTY_CURR_XPATH, base + 2);
	if (!yang_dnode_exists(vty->candidate_config->dnode, check)) {
		vty_out(vty, "%% Specify remote-as or peer-group commands first\n");
		return -1;
	}

	afi_safi = bgp_cli_afi_safi_name(vty->node);
	/*
	 * Peer AF xpath is the afi-safi list entry only. Leaf "enabled"
	 * (neighbor activate) lives directly on the list entry; other
	 * knobs append "/<af>/..." themselves (e.g. /ipv4-unicast/...).
	 */
	snprintfrr(xpath, xpath_len, "%s/afi-safis/afi-safi[afi-safi-name='frr-routing:%s']", base,
		   afi_safi);
	return 0;
}

DEFPY_YANG(neighbor_dampening_yang, neighbor_dampening_yang_cmd,
	   "neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor dampening [(1-45)$half [(1-20000)$reuse (1-20000)$suppress (1-255)$max]]",
	   NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Enable neighbor route-flap dampening\n"
	   "Half-life time for the penalty\n"
	   "Value to start reusing a route\n"
	   "Value to start suppressing a route\n"
	   "Maximum duration to suppress a stable route\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	char half_buf[16], reuse_buf[16], suppress_buf[16], max_buf[16];
	bool is_pg = false;
	unsigned int half_min, reuse_val, suppress_val, max_min;
	int ret;

	if (suppress_str && reuse_str && (unsigned int)suppress < (unsigned int)reuse) {
		vty_out(vty, "Suppress value cannot be less than reuse value\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ret = bgp_cli_peer_af_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	/* Dampening leaves live under afi-safi/<af>/route-flap-dampening. */
	{
		const char *af = bgp_cli_afi_safi_name(vty->node);
		size_t len = strlen(xpath);

		snprintfrr(xpath + len, sizeof(xpath) - len, "/%s", af);
	}

	half_min = half_str ? (unsigned int)half : DEFAULT_HALF_LIFE;
	reuse_val = reuse_str ? (unsigned int)reuse : DEFAULT_REUSE;
	suppress_val = suppress_str ? (unsigned int)suppress : DEFAULT_SUPPRESS;
	max_min = max_str ? (unsigned int)max : (4 * half_min);

	snprintfrr(leaf, sizeof(leaf), "%s/route-flap-dampening/enable", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, "true");

	snprintfrr(leaf, sizeof(leaf), "%s/route-flap-dampening/reach-decay", xpath);
	snprintfrr(half_buf, sizeof(half_buf), "%u", half_min);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, half_buf);

	snprintfrr(leaf, sizeof(leaf), "%s/route-flap-dampening/reuse-above", xpath);
	snprintfrr(reuse_buf, sizeof(reuse_buf), "%u", reuse_val);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, reuse_buf);

	snprintfrr(leaf, sizeof(leaf), "%s/route-flap-dampening/suppress-above", xpath);
	snprintfrr(suppress_buf, sizeof(suppress_buf), "%u", suppress_val);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, suppress_buf);

	snprintfrr(leaf, sizeof(leaf), "%s/route-flap-dampening/unreach-decay", xpath);
	snprintfrr(max_buf, sizeof(max_buf), "%u", max_min);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, max_buf);

	return nb_cli_apply_changes(vty, NULL);
}


DEFPY_YANG(no_neighbor_dampening_yang, no_neighbor_dampening_yang_cmd,
	   "no neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor dampening [HALF [REUSE SUPPRESS MAX]]",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Enable neighbor route-flap dampening\n"
	   "Half-life time for the penalty\n"
	   "Value to start reusing a route\n"
	   "Value to start suppressing a route\n"
	   "Maximum duration to suppress a stable route\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	int ret;

	ret = bgp_cli_peer_af_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	/* Dampening leaves live under afi-safi/<af>/route-flap-dampening. */
	{
		const char *af = bgp_cli_afi_safi_name(vty->node);
		size_t len = strlen(xpath);

		snprintfrr(xpath + len, sizeof(xpath) - len, "/%s", af);
	}

	snprintfrr(leaf, sizeof(leaf), "%s/route-flap-dampening/enable", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/route-flap-dampening/reach-decay", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/route-flap-dampening/reuse-above", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/route-flap-dampening/suppress-above", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/route-flap-dampening/unreach-decay", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_activate_yang, neighbor_activate_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor activate",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Enable the Address Family for this Neighbor\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	int ret;

	ret = bgp_cli_peer_af_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/enabled", xpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_soft_reconfiguration_yang,
	   neighbor_soft_reconfiguration_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor soft-reconfiguration inbound",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Per neighbor soft reconfiguration\n"
	   "Allow inbound soft reconfiguration for this neighbor\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	const char *af;
	int ret;

	ret = bgp_cli_peer_af_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	af = bgp_cli_afi_safi_name(vty->node);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/%s/soft-reconfiguration", xpath, af);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_encap_srv6_yang, neighbor_encap_srv6_yang_cmd,
	   "[no] neighbor <X:X::X:X|WORD>$neighbor <encapsulation-srv6|encapsulation-srv6-relax>$encap",
	   NO_STR NEIGHBOR_STR
	   "Neighbor IPv6 address\n"
	   "Neighbor tag\n"
	   "Advertise routes with SRv6 prefix SID to the neighbor\n"
	   "Advertise routes with and without SRv6 prefix SID the neighbor\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	const char *af;
	const char *yang_val;
	struct peer *peer;
	afi_t afi;
	safi_t safi = SAFI_UNICAST;
	uint64_t flag;
	int ret;

	ret = bgp_cli_peer_af_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	af = bgp_cli_afi_safi_name(vty->node);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	yang_val = strmatch(encap, "encapsulation-srv6-relax") ? "srv6-relax" : "srv6";
	flag = strmatch(encap, "encapsulation-srv6-relax")
		       ? PEER_FLAG_CONFIG_ENCAPSULATION_SRV6_RELAX
		       : PEER_FLAG_CONFIG_ENCAPSULATION_SRV6;
	snprintfrr(leaf, sizeof(leaf), "%s/%s/encapsulation/type[.='%s']", xpath, af, yang_val);

	if (no) {
		peer = peer_and_group_lookup_vty(vty, neighbor);
		if (!peer)
			return CMD_WARNING_CONFIG_FAILED;
		afi = bgp_node_afi(vty);
		if (!peergroup_af_flag_check(peer, afi, safi, flag)) {
			vty_out(vty, "%% Peer is not configured.\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	} else
		nb_cli_enqueue_change(vty, leaf, NB_OP_CREATE, yang_val);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_encapsulation_srv6_or_mpls_yang,
	   neighbor_encapsulation_srv6_or_mpls_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$peer_str <encapsulation-srv6$srv6|encapsulation-mpls$mpls>",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Distribute L3VPN updates with SRv6 prefix SID\n"
	   "Distribute L3VPN updates with MPLS prefix SID\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	const char *af;
	const char *yang_val;
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	uint64_t flag;
	int ret;

	ret = bgp_cli_peer_af_xpath(vty, peer_str, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	af = bgp_cli_afi_safi_name(vty->node);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	yang_val = srv6 ? "srv6" : "mpls";
	flag = srv6 ? PEER_FLAG_CONFIG_ENCAPSULATION_SRV6 : PEER_FLAG_CONFIG_ENCAPSULATION_MPLS;
	snprintfrr(leaf, sizeof(leaf), "%s/%s/encapsulation/type[.='%s']", xpath, af, yang_val);

	if (no) {
		peer = peer_and_group_lookup_vty(vty, peer_str);
		if (!peer)
			return CMD_WARNING_CONFIG_FAILED;
		afi = bgp_node_afi(vty);
		safi = bgp_node_safi(vty);

		if (!peergroup_af_flag_check(peer, afi, safi, flag))
			return CMD_SUCCESS;

		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	} else
		nb_cli_enqueue_change(vty, leaf, NB_OP_CREATE, yang_val);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_nexthop_self_yang, neighbor_nexthop_self_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor next-hop-self [<force|all>$force]",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Disable the next hop calculation for this neighbor\n"
	   "Set the next hop to self for reflected routes\n"
	   "Set the next hop to self for reflected routes\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	const char *af;
	int ret;

	ret = bgp_cli_peer_af_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	af = bgp_cli_afi_safi_name(vty->node);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	if (force) {
		snprintfrr(leaf, sizeof(leaf), "%s/%s/nexthop-self/next-hop-self-force", xpath, af);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, no ? "false" : "true");
	} else {
		snprintfrr(leaf, sizeof(leaf), "%s/%s/nexthop-self/next-hop-self", xpath, af);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, no ? "false" : "true");
	}
	return nb_cli_apply_changes(vty, NULL);
}

/* EVPN never had the "all" keyword. force and all share one handler. */
ALIAS_ATTR(neighbor_nexthop_self_yang, neighbor_nexthop_self_evpn_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor next-hop-self [force$force]",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Disable the next hop calculation for this neighbor\n"
	   "Set the next hop to self for reflected routes\n",
	   CMD_ATTR_YANG);

DEFPY_YANG(neighbor_attr_unchanged_yang, neighbor_attr_unchanged_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor attribute-unchanged [{as-path$aspath|next-hop$nexthop|med$med}]",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "BGP attribute is propagated unchanged to this neighbor\n"
	   "As-path attribute\n"
	   "Nexthop attribute\n"
	   "Med attribute\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	const char *af;
	const char *val;
	bool all;
	int ret;

	ret = bgp_cli_peer_af_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	af = bgp_cli_afi_safi_name(vty->node);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	all = !aspath && !nexthop && !med;
	val = no ? "false" : "true";

	if (all || aspath) {
		snprintfrr(leaf, sizeof(leaf), "%s/%s/attr-unchanged/as-path-unchanged", xpath, af);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, val);
	}
	if (all || nexthop) {
		snprintfrr(leaf, sizeof(leaf), "%s/%s/attr-unchanged/next-hop-unchanged", xpath,
			   af);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, val);
	}
	if (all || med) {
		snprintfrr(leaf, sizeof(leaf), "%s/%s/attr-unchanged/med-unchanged", xpath, af);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, val);
	}

	/* Classic sets unspecified flags off when a subset is given. */
	if (!no && !all) {
		if (!aspath) {
			snprintfrr(leaf, sizeof(leaf), "%s/%s/attr-unchanged/as-path-unchanged",
				   xpath, af);
			nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, "false");
		}
		if (!nexthop) {
			snprintfrr(leaf, sizeof(leaf), "%s/%s/attr-unchanged/next-hop-unchanged",
				   xpath, af);
			nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, "false");
		}
		if (!med) {
			snprintfrr(leaf, sizeof(leaf), "%s/%s/attr-unchanged/med-unchanged", xpath,
				   af);
			nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, "false");
		}
	}

	return nb_cli_apply_changes(vty, NULL);
}


static int bgp_cli_peer_af_bool(struct vty *vty, const char *neighbor, const char *relpath, bool no)
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	const char *af;
	int ret;

	ret = bgp_cli_peer_af_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	af = bgp_cli_afi_safi_name(vty->node);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/%s/%s", xpath, af, relpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_as_override_yang, neighbor_as_override_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor as-override",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Override ASNs in outbound updates if aspath equals remote-as\n")
{
	return bgp_cli_peer_af_bool(vty, neighbor, "as-path-options/replace-peer-as", !!no);
}

DEFPY_YANG(neighbor_remove_private_as_yang,
	   neighbor_remove_private_as_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor remove-private-AS [all$all] [replace-AS$replace]",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Remove private ASNs in outbound updates\n"
	   "Apply to all AS numbers\n"
	   "Replace private ASNs with our ASN in outbound updates\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	const char *af;
	const char *active;
	int ret;
	static const char *const variants[] = {
		"private-as/remove-private-as",
		"private-as/remove-private-as-all",
		"private-as/remove-private-as-replace",
		"private-as/remove-private-as-all-replace",
	};

	ret = bgp_cli_peer_af_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	af = bgp_cli_afi_safi_name(vty->node);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	if (all && replace)
		active = variants[3];
	else if (all)
		active = variants[1];
	else if (replace)
		active = variants[2];
	else
		active = variants[0];

	if (no) {
		snprintfrr(leaf, sizeof(leaf), "%s/%s/%s", xpath, af, active);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, "false");
	} else {
		/* Keep YANG exclusive: clear other variants when setting one. */
		for (size_t i = 0; i < array_size(variants); i++) {
			snprintfrr(leaf, sizeof(leaf), "%s/%s/%s", xpath, af, variants[i]);
			nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY,
					      variants[i] == active ? "true" : "false");
		}
	}
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_route_reflector_client_yang,
	   neighbor_route_reflector_client_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor route-reflector-client",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Configure a neighbor as Route Reflector client\n")
{
	return bgp_cli_peer_af_bool(vty, neighbor, "route-reflector/route-reflector-client", !!no);
}

DEFPY_YANG(neighbor_route_server_client_yang,
	   neighbor_route_server_client_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor route-server-client",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Configure a neighbor as Route Server client\n")
{
	return bgp_cli_peer_af_bool(vty, neighbor, "route-server/route-server-client", !!no);
}


DEFPY_YANG(neighbor_weight_yang, neighbor_weight_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor weight [(0-65535)$weight]",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Set default weight for routes from this neighbor\n"
	   "default weight\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	const char *af;
	char buf[16];
	int ret;

	ret = bgp_cli_peer_af_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	af = bgp_cli_afi_safi_name(vty->node);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/%s/weight/weight-attribute", xpath, af);
	if (no)
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	else {
		if (!weight_str)
			return CMD_WARNING_CONFIG_FAILED;
		snprintfrr(buf, sizeof(buf), "%" PRId64, weight);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, buf);
	}
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_send_community_yang, neighbor_send_community_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor send-community [<both|all|extended|standard|large>$type]",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Send Community attribute to this neighbor\n"
	   "Send Standard and Extended Community attributes\n"
	   "Send Standard, Large and Extended Community attributes\n"
	   "Send Extended Community attributes\n"
	   "Send Standard Community attributes\n"
	   "Send Large Community attributes\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	const char *af;
	const char *val;
	bool do_std = false, do_ext = false, do_large = false;
	int ret;

	ret = bgp_cli_peer_af_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	af = bgp_cli_afi_safi_name(vty->node);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	/* Bare send-community (no type) => standard only, like classic. */
	if (!type || strmatch(type, "standard"))
		do_std = true;
	else if (strmatch(type, "extended"))
		do_ext = true;
	else if (strmatch(type, "large"))
		do_large = true;
	else if (strmatch(type, "both")) {
		do_std = true;
		do_ext = true;
	} else { /* all */
		do_std = true;
		do_ext = true;
		do_large = true;
	}
	val = no ? "false" : "true";

	if (do_std) {
		snprintfrr(leaf, sizeof(leaf), "%s/%s/send-community/send-community", xpath, af);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, val);
	}
	if (do_ext) {
		snprintfrr(leaf, sizeof(leaf), "%s/%s/send-community/send-ext-community", xpath,
			   af);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, val);
	}
	if (do_large) {
		snprintfrr(leaf, sizeof(leaf), "%s/%s/send-community/send-large-community", xpath,
			   af);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, val);
	}
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_send_community_rpki_yang,
	   neighbor_send_community_rpki_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor send-community extended rpki",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Send Community attribute to this neighbor\n"
	   "Send Extended Community attributes\n"
	   "Send RPKI Extended Community attributes\n")
{
	return bgp_cli_peer_af_bool(vty, neighbor, "send-community/send-ext-community-rpki", !!no);
}


DEFPY_YANG(neighbor_allowas_in_yang, neighbor_allowas_in_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor allowas-in [route-map ![RMAP_NAME$rmap_name]] [<(1-10)$allow_num|origin$origin_kw>]",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Accept as-path with my AS present in it\n"
	   "Filter routes using route-map\n"
	   "Name of route-map\n"
	   "Number of occurrences of AS number\n"
	   "Only accept my AS in the as-path if the route was originated in my AS\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	const char *af;
	char buf[8];
	int ret;

	ret = bgp_cli_peer_af_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	af = bgp_cli_afi_safi_name(vty->node);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	if (no) {
		snprintfrr(leaf, sizeof(leaf), "%s/%s/as-path-options/allowas-in-route-map", xpath,
			   af);
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
		snprintfrr(leaf, sizeof(leaf), "%s/%s/as-path-options/allow-own-as", xpath, af);
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
		snprintfrr(leaf, sizeof(leaf), "%s/%s/as-path-options/allow-own-origin-as", xpath,
			   af);
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
		return nb_cli_apply_changes(vty, NULL);
	}

	if (origin_kw) {
		snprintfrr(leaf, sizeof(leaf), "%s/%s/as-path-options/allow-own-as", xpath, af);
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
		snprintfrr(leaf, sizeof(leaf), "%s/%s/as-path-options/allow-own-origin-as", xpath,
			   af);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, "true");
	} else {
		unsigned int num = allow_num ? (unsigned int)allow_num : BGP_ALLOWAS_IN_DEFAULT;

		snprintfrr(leaf, sizeof(leaf), "%s/%s/as-path-options/allow-own-origin-as", xpath,
			   af);
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
		snprintfrr(buf, sizeof(buf), "%u", num);
		snprintfrr(leaf, sizeof(leaf), "%s/%s/as-path-options/allow-own-as", xpath, af);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, buf);
	}

	snprintfrr(leaf, sizeof(leaf), "%s/%s/as-path-options/allowas-in-route-map", xpath, af);
	if (rmap_name)
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, rmap_name);
	else
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_default_originate_yang,
	   neighbor_default_originate_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor default-originate [route-map RMAP_NAME$rmap]",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Originate default route to this neighbor\n"
	   "Route-map to specify criteria to originate default\n"
	   "route-map name\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	const char *af;
	int ret;

	ret = bgp_cli_peer_af_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	af = bgp_cli_afi_safi_name(vty->node);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintfrr(leaf, sizeof(leaf), "%s/%s/default-originate/route-map", xpath, af);
	if (no || !rmap)
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, rmap);

	snprintfrr(leaf, sizeof(leaf), "%s/%s/default-originate/originate", xpath, af);
	if (no)
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, "false");
	else
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, "true");

	return nb_cli_apply_changes(vty, NULL);
}


static int bgp_cli_peer_af_filter_leaf(struct vty *vty, const char *neighbor, const char *leaf_rel,
				       const char *name, bool no)
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	const char *af;
	int ret;

	ret = bgp_cli_peer_af_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	af = bgp_cli_afi_safi_name(vty->node);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/%s/filter-config/%s", xpath, af, leaf_rel);
	if (no)
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, name);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_prefix_list_yang, neighbor_prefix_list_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor prefix-list WORD$name <in|out>$dir",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Filter updates to/from this neighbor\n"
	   "Name of a prefix list\n"
	   "Filter incoming updates\n"
	   "Filter outgoing updates\n")
{
	const char *leaf = strmatch(dir, "in") ? "plist-import" : "plist-export";

	return bgp_cli_peer_af_filter_leaf(vty, neighbor, leaf, name, !!no);
}

DEFPY_YANG(neighbor_distribute_list_yang, neighbor_distribute_list_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor distribute-list ACCESSLIST_NAME$name <in|out>$dir",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Filter updates to/from this neighbor\n"
	   "IP Access-list name\n"
	   "Filter incoming updates\n"
	   "Filter outgoing updates\n")
{
	const char *leaf = strmatch(dir, "in") ? "access-list-import" : "access-list-export";

	return bgp_cli_peer_af_filter_leaf(vty, neighbor, leaf, name, !!no);
}

DEFPY_YANG(neighbor_filter_list_yang, neighbor_filter_list_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor filter-list AS_PATH_FILTER_NAME$name <in|out>$dir",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Establish BGP filters\n"
	   "AS path access-list name\n"
	   "Filter incoming routes\n"
	   "Filter outgoing routes\n")
{
	const char *leaf = strmatch(dir, "in") ? "as-path-filter-list-import"
					       : "as-path-filter-list-export";

	return bgp_cli_peer_af_filter_leaf(vty, neighbor, leaf, name, !!no);
}

DEFPY_YANG(neighbor_route_map_yang, neighbor_route_map_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor route-map RMAP_NAME$name <in|out>$dir",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Apply route map to neighbor\n"
	   "Name of route map\n"
	   "Apply map to incoming routes\n"
	   "Apply map to outbound routes\n")
{
	const char *leaf = strmatch(dir, "in") ? "rmap-import" : "rmap-export";

	return bgp_cli_peer_af_filter_leaf(vty, neighbor, leaf, name, !!no);
}

DEFPY_YANG(neighbor_unsuppress_map_yang, neighbor_unsuppress_map_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor unsuppress-map RMAP_NAME$name",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Route-map to selectively unsuppress suppressed routes\n"
	   "Name of route map\n")
{
	return bgp_cli_peer_af_filter_leaf(vty, neighbor, "unsuppress-map-export", name, !!no);
}


static void bgp_cli_clear_prefix_limit_options(struct vty *vty, const char *base)
{
	char leaf[XPATH_MAXLEN + 256];
	static const char *const opts[] = {
		"options/warning-only",		  "options/restart-timer",
		"options/shutdown-threshold-pct", "options/tr-shutdown-threshold-pct",
		"options/tr-restart-timer",	  "options/tw-shutdown-threshold-pct",
		"options/tw-warning-only",
	};
	size_t i;

	for (i = 0; i < array_size(opts); i++) {
		snprintfrr(leaf, sizeof(leaf), "%s/%s", base, opts[i]);
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	}
}

DEFPY_YANG(neighbor_maximum_prefix_yang, neighbor_maximum_prefix_yang_cmd,
	   "neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor maximum-prefix (1-4294967295)$max [(1-100)$threshold] [<warning-only$warn|restart (1-65535)$restart>] [force$force]",
	   NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Maximum number of prefix accept from this peer\n"
	   "maximum no. of prefix limit\n"
	   "Threshold value (%) at which to generate a warning msg\n"
	   "Only give warning message when limit is exceeded\n"
	   "Restart bgp connection after limit is exceeded\n"
	   "Restart interval in minutes\n"
	   "Force checking all received routes not only accepted\n")
{
	char xpath[XPATH_MAXLEN];
	char dirpath[XPATH_MAXLEN + 256];
	char leaf[XPATH_MAXLEN + 512];
	bool is_pg = false;
	const char *af;
	char max_buf[16], threshold_buf[16], restart_buf[16];
	int ret;

	ret = bgp_cli_peer_af_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	af = bgp_cli_afi_safi_name(vty->node);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintfrr(dirpath, sizeof(dirpath), "%s/%s/prefix-limit/direction-list[direction='in']",
		   xpath, af);

	nb_cli_enqueue_change(vty, dirpath, NB_OP_CREATE, NULL);
	snprintfrr(max_buf, sizeof(max_buf), "%" PRId64, max);
	snprintfrr(leaf, sizeof(leaf), "%s/max-prefixes", dirpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, max_buf);

	snprintfrr(leaf, sizeof(leaf), "%s/force-check", dirpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, force ? "true" : "false");

	bgp_cli_clear_prefix_limit_options(vty, dirpath);

	if (threshold_str && warn) {
		snprintfrr(threshold_buf, sizeof(threshold_buf), "%" PRId64, threshold);
		snprintfrr(leaf, sizeof(leaf), "%s/options/tw-shutdown-threshold-pct", dirpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, threshold_buf);
		snprintfrr(leaf, sizeof(leaf), "%s/options/tw-warning-only", dirpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, "true");
	} else if (threshold_str && restart_str) {
		snprintfrr(threshold_buf, sizeof(threshold_buf), "%" PRId64, threshold);
		snprintfrr(leaf, sizeof(leaf), "%s/options/tr-shutdown-threshold-pct", dirpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, threshold_buf);
		snprintfrr(restart_buf, sizeof(restart_buf), "%" PRId64, restart);
		snprintfrr(leaf, sizeof(leaf), "%s/options/tr-restart-timer", dirpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, restart_buf);
	} else if (threshold_str) {
		snprintfrr(threshold_buf, sizeof(threshold_buf), "%" PRId64, threshold);
		snprintfrr(leaf, sizeof(leaf), "%s/options/shutdown-threshold-pct", dirpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, threshold_buf);
	} else if (warn) {
		snprintfrr(leaf, sizeof(leaf), "%s/options/warning-only", dirpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, "true");
	} else if (restart_str) {
		snprintfrr(restart_buf, sizeof(restart_buf), "%" PRId64, restart);
		snprintfrr(leaf, sizeof(leaf), "%s/options/restart-timer", dirpath);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, restart_buf);
	}

	return nb_cli_apply_changes(vty, NULL);
}


DEFPY_YANG(no_neighbor_maximum_prefix_yang, no_neighbor_maximum_prefix_yang_cmd,
	   "no neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor maximum-prefix [(1-4294967295) [(1-100)] [restart (1-65535)] [warning-only] [force]]",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Maximum number of prefix accept from this peer\n"
	   "maximum no. of prefix limit\n"
	   "Threshold value (%) at which to generate a warning msg\n"
	   "Restart bgp connection after limit is exceeded\n"
	   "Restart interval in minutes\n"
	   "Only give warning message when limit is exceeded\n"
	   "Force checking all received routes not only accepted\n")
{
	char xpath[XPATH_MAXLEN];
	char dirpath[XPATH_MAXLEN + 256];
	bool is_pg = false;
	const char *af;
	int ret;

	ret = bgp_cli_peer_af_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	af = bgp_cli_afi_safi_name(vty->node);
	snprintfrr(dirpath, sizeof(dirpath), "%s/%s/prefix-limit/direction-list[direction='in']",
		   xpath, af);
	nb_cli_enqueue_change(vty, dirpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_maximum_prefix_out_yang,
	   neighbor_maximum_prefix_out_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor maximum-prefix-out [(1-4294967295)$max]",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Maximum number of prefixes to be sent to this peer\n"
	   "Maximum no. of prefix limit\n")
{
	char xpath[XPATH_MAXLEN];
	char dirpath[XPATH_MAXLEN + 256];
	char leaf[XPATH_MAXLEN + 512];
	bool is_pg = false;
	const char *af;
	char buf[16];
	int ret;

	ret = bgp_cli_peer_af_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	af = bgp_cli_afi_safi_name(vty->node);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintfrr(dirpath, sizeof(dirpath), "%s/%s/prefix-limit/direction-list[direction='out']",
		   xpath, af);

	if (no) {
		nb_cli_enqueue_change(vty, dirpath, NB_OP_DESTROY, NULL);
		return nb_cli_apply_changes(vty, NULL);
	}
	if (!max_str)
		return CMD_WARNING_CONFIG_FAILED;

	nb_cli_enqueue_change(vty, dirpath, NB_OP_CREATE, NULL);
	snprintfrr(buf, sizeof(buf), "%" PRId64, max);
	snprintfrr(leaf, sizeof(leaf), "%s/max-prefixes", dirpath);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, buf);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_addpath_tx_yang, neighbor_addpath_tx_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor <addpath-tx-all-paths$all|addpath-tx-bestpath-per-AS$peras>",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Use addpath to advertise all paths to a neighbor\n"
	   "Use addpath to advertise the bestpath per each neighboring AS\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	const char *af;
	const char *type;
	int ret;

	ret = bgp_cli_peer_af_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	af = bgp_cli_afi_safi_name(vty->node);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintfrr(leaf, sizeof(leaf), "%s/%s/add-paths/best-selected-paths", xpath, af);
	nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);

	snprintfrr(leaf, sizeof(leaf), "%s/%s/add-paths/path-type", xpath, af);
	if (no)
		type = "none";
	else if (all)
		type = "all";
	else
		type = "per-as";
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, type);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_addpath_tx_best_selected_yang,
	   neighbor_addpath_tx_best_selected_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor addpath-tx-best-selected [(1-6)$paths]",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Use addpath to advertise best selected paths to a neighbor\n"
	   "The number of best paths\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	const char *af;
	char buf[8];
	int ret;

	ret = bgp_cli_peer_af_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	af = bgp_cli_afi_safi_name(vty->node);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintfrr(leaf, sizeof(leaf), "%s/%s/add-paths/path-type", xpath, af);
	if (no) {
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, "none");
		snprintfrr(leaf, sizeof(leaf), "%s/%s/add-paths/best-selected-paths", xpath, af);
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
		return nb_cli_apply_changes(vty, NULL);
	}
	if (!paths_str)
		return CMD_WARNING_CONFIG_FAILED;

	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, "best-selected");
	snprintfrr(buf, sizeof(buf), "%" PRId64, paths);
	snprintfrr(leaf, sizeof(leaf), "%s/%s/add-paths/best-selected-paths", xpath, af);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, buf);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_disable_addpath_rx_yang,
	   neighbor_disable_addpath_rx_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor disable-addpath-rx",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Do not accept additional paths\n")
{
	return bgp_cli_peer_af_bool(vty, neighbor, "add-paths/disable-addpath-rx", !!no);
}

DEFPY_YANG(neighbor_addpath_rx_paths_limit_yang,
	   neighbor_addpath_rx_paths_limit_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor addpath-rx-paths-limit [(1-65535)$paths_limit]",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Paths Limit for Addpath to receive from the peer\n"
	   "Maximum number of paths\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	const char *af;
	char buf[16];
	int ret;

	ret = bgp_cli_peer_af_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	af = bgp_cli_afi_safi_name(vty->node);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/%s/add-paths/addpath-rx-paths-limit", xpath, af);
	if (no)
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	else {
		if (!paths_limit_str)
			return CMD_WARNING_CONFIG_FAILED;
		snprintfrr(buf, sizeof(buf), "%" PRId64, paths_limit);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, buf);
	}
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_advertise_map_yang, neighbor_advertise_map_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor advertise-map RMAP_NAME$advertise_str <exist-map|non-exist-map>$exist RMAP_NAME$condition_str",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Route-map to conditionally advertise routes\n"
	   "Name of advertise map\n"
	   "Advertise routes only if prefixes in exist-map are installed in BGP table\n"
	   "Advertise routes only if prefixes in non-exist-map are not installed in BGP table\n"
	   "Name of the exist or non exist map\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	const char *af;
	int ret;

	ret = bgp_cli_peer_af_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	af = bgp_cli_afi_safi_name(vty->node);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	if (no) {
		/* Destroy the whole container so leaf destroy order cannot
		 * re-apply conditional-advertisement via sibling leaves.
		 */
		snprintfrr(leaf, sizeof(leaf), "%s/%s/conditional-advertisement", xpath, af);
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
		return nb_cli_apply_changes(vty, NULL);
	}

	snprintfrr(leaf, sizeof(leaf), "%s/%s/conditional-advertisement/advertise-map", xpath, af);
	nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, advertise_str);

	if (strmatch(exist, "exist-map")) {
		snprintfrr(leaf, sizeof(leaf), "%s/%s/conditional-advertisement/non-exist-map",
			   xpath, af);
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
		snprintfrr(leaf, sizeof(leaf), "%s/%s/conditional-advertisement/exist-map", xpath,
			   af);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, condition_str);
	} else {
		snprintfrr(leaf, sizeof(leaf), "%s/%s/conditional-advertisement/exist-map", xpath,
			   af);
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
		snprintfrr(leaf, sizeof(leaf), "%s/%s/conditional-advertisement/non-exist-map",
			   xpath, af);
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, condition_str);
	}
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_accept_own_yang, neighbor_accept_own_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor accept-own",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Enable handling of self-originated VPN routes containing ACCEPT_OWN community\n")
{
	return bgp_cli_peer_af_bool(vty, neighbor, "accept-own", !!no);
}

DEFPY_YANG(neighbor_soo_yang, neighbor_soo_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor soo [ASN:NN_OR_IP-ADDRESS:NN$soo]",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Set the Site-of-Origin (SoO) extended community\n"
	   "VPN extended community\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	const char *af;
	int ret;

	ret = bgp_cli_peer_af_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	af = bgp_cli_afi_safi_name(vty->node);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintfrr(leaf, sizeof(leaf), "%s/%s/soo", xpath, af);
	if (no)
		nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	else {
		if (!soo)
			return CMD_WARNING_CONFIG_FAILED;
		nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, soo);
	}
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_upa_yang, neighbor_upa_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor upa",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Send UPA (Unreachable Prefix Announcement) routes to this neighbor\n")
{
	return bgp_cli_peer_af_bool(vty, neighbor, "upa", !!no);
}

DEFPY_YANG(neighbor_capability_orf_yang, neighbor_capability_orf_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor capability orf prefix-list <both|send|receive>$dir",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Advertise capability to the peer\n"
	   "Advertise ORF capability to the peer\n"
	   "Advertise prefixlist ORF capability to this neighbor\n"
	   "Capability to SEND and RECEIVE the ORF to/from this neighbor\n"
	   "Capability to SEND the ORF to this neighbor\n"
	   "Capability to RECEIVE the ORF from this neighbor\n")
{
	char xpath[XPATH_MAXLEN];
	char leaf[XPATH_MAXLEN + 256];
	bool is_pg = false;
	const char *af;
	const char *active;
	static const char *const variants[] = {
		"orf-capability/orf-send",
		"orf-capability/orf-receive",
		"orf-capability/orf-both",
	};
	size_t i;
	int ret;

	ret = bgp_cli_peer_af_xpath(vty, neighbor, xpath, sizeof(xpath), &is_pg);
	if (ret != 0)
		return CMD_WARNING_CONFIG_FAILED;

	af = bgp_cli_afi_safi_name(vty->node);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	if (strmatch(dir, "send"))
		active = variants[0];
	else if (strmatch(dir, "receive"))
		active = variants[1];
	else
		active = variants[2];

	for (i = 0; i < array_size(variants); i++) {
		snprintfrr(leaf, sizeof(leaf), "%s/%s/%s", xpath, af, variants[i]);
		if (no) {
			if (variants[i] == active)
				nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
		} else if (variants[i] == active)
			nb_cli_enqueue_change(vty, leaf, NB_OP_MODIFY, "true");
		else
			nb_cli_enqueue_change(vty, leaf, NB_OP_DESTROY, NULL);
	}
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(neighbor_nexthop_local_unchanged_yang,
	   neighbor_nexthop_local_unchanged_yang_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor nexthop-local unchanged",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Configure treatment of outgoing link-local nexthop attribute\n"
	   "Leave link-local nexthop unchanged for this peer\n")
{
	return bgp_cli_peer_af_bool(vty, neighbor, "nexthop-local-unchanged", !!no);
}

ALIAS_ATTR(neighbor_nexthop_local_unchanged_yang, neighbor_nexthop_local_unchanged_yang_hidden_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor nexthop-local unchanged",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Configure treatment of outgoing link-local nexthop attribute\n"
	   "Leave link-local nexthop unchanged for this peer\n",
	   CMD_ATTR_YANG | CMD_ATTR_HIDDEN);

ALIAS_ATTR(
	neighbor_advertise_map_yang, neighbor_advertise_map_yang_hidden_cmd,
	"[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor advertise-map RMAP_NAME$advertise_str <exist-map|non-exist-map>$exist RMAP_NAME$condition_str",
	NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	"Route-map to conditionally advertise routes\n"
	"Name of advertise map\n"
	"Advertise routes only if prefixes in exist-map are installed in BGP table\n"
	"Advertise routes only if prefixes in non-exist-map are not installed in BGP table\n"
	"Name of the exist or non exist map\n",
	CMD_ATTR_YANG | CMD_ATTR_HIDDEN);

ALIAS_ATTR(neighbor_upa_yang, neighbor_upa_yang_hidden_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor upa",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Send UPA (Unreachable Prefix Announcement) routes to this neighbor\n",
	   CMD_ATTR_YANG | CMD_ATTR_HIDDEN);

ALIAS_ATTR(
	neighbor_capability_orf_yang, neighbor_capability_orf_yang_hidden_cmd,
	"[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor capability orf prefix-list <both|send|receive>$dir",
	NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	"Advertise capability to the peer\n"
	"Advertise ORF capability to the peer\n"
	"Advertise prefixlist ORF capability to this neighbor\n"
	"Capability to SEND and RECEIVE the ORF to/from this neighbor\n"
	"Capability to SEND the ORF to this neighbor\n"
	"Capability to RECEIVE the ORF from this neighbor\n",
	CMD_ATTR_YANG | CMD_ATTR_HIDDEN);

ALIAS_ATTR(
	neighbor_maximum_prefix_yang, neighbor_maximum_prefix_yang_hidden_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor maximum-prefix (1-4294967295)$max [(1-100)$threshold] [<warning-only$warn|restart (1-65535)$restart>] [force$force]",
	NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	"Maximum number of prefix accept from this peer\n"
	"maximum no. of prefix limit\n"
	"Threshold value (%) at which to generate a warning msg\n"
	"Only give warning message when limit is exceeded\n"
	"Restart bgp connection after limit is exceeded\n"
	"Restart interval in minutes\n"
	"Force checking all received routes not only accepted\n",
	CMD_ATTR_YANG | CMD_ATTR_HIDDEN);


ALIAS_ATTR(no_neighbor_maximum_prefix_yang, no_neighbor_maximum_prefix_yang_hidden_cmd,
	   "no neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor maximum-prefix [(1-4294967295) [(1-100)] [restart (1-65535)] [warning-only] [force]]",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Maximum number of prefix accept from this peer\n"
	   "maximum no. of prefix limit\n"
	   "Threshold value (%) at which to generate a warning msg\n"
	   "Restart bgp connection after limit is exceeded\n"
	   "Restart interval in minutes\n"
	   "Only give warning message when limit is exceeded\n"
	   "Force checking all received routes not only accepted\n",
	   CMD_ATTR_YANG | CMD_ATTR_HIDDEN);

ALIAS_ATTR(neighbor_maximum_prefix_out_yang, neighbor_maximum_prefix_out_yang_hidden_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor maximum-prefix-out [(1-4294967295)$max]",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Maximum number of prefixes to be sent to this peer\n"
	   "Maximum no. of prefix limit\n",
	   CMD_ATTR_YANG | CMD_ATTR_HIDDEN);

ALIAS_ATTR(
	neighbor_addpath_tx_yang, neighbor_addpath_tx_yang_hidden_cmd,
	"[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor <addpath-tx-all-paths$all|addpath-tx-bestpath-per-AS$peras>",
	NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR
	"Use addpath to advertise all paths to a neighbor\n"
	"Use addpath to advertise the bestpath per each neighboring AS\n"
	"Use addpath to advertise best selected paths to a neighbor\n",
	CMD_ATTR_YANG | CMD_ATTR_HIDDEN);

ALIAS_ATTR(neighbor_addpath_tx_best_selected_yang,
	   neighbor_addpath_tx_best_selected_yang_hidden_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor addpath-tx-best-selected [(1-6)$paths]",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Use addpath to advertise best selected paths to a neighbor\n"
	   "The number of best paths\n",
	   CMD_ATTR_YANG | CMD_ATTR_HIDDEN);

ALIAS_ATTR(neighbor_disable_addpath_rx_yang, neighbor_disable_addpath_rx_yang_hidden_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor disable-addpath-rx",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2 "Do not accept additional paths\n",
	   CMD_ATTR_YANG | CMD_ATTR_HIDDEN);

ALIAS_ATTR(
	neighbor_addpath_rx_paths_limit_yang, neighbor_addpath_rx_paths_limit_yang_hidden_cmd,
	"[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor addpath-rx-paths-limit [(1-65535)$paths_limit]",
	NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2 "Paths Limit for Addpath to receive from the peer\n"
					       "Maximum number of paths\n",
	CMD_ATTR_YANG | CMD_ATTR_HIDDEN);

ALIAS_ATTR(neighbor_prefix_list_yang, neighbor_prefix_list_yang_hidden_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor prefix-list WORD$name <in|out>$dir",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2 "Filter updates to/from this neighbor\n"
						  "Name of a prefix list\n"
						  "Filter incoming updates\n"
						  "Filter outgoing updates\n",
	   CMD_ATTR_YANG | CMD_ATTR_HIDDEN);

ALIAS_ATTR(
	neighbor_distribute_list_yang, neighbor_distribute_list_yang_hidden_cmd,
	"[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor distribute-list ACCESSLIST_NAME$name <in|out>$dir",
	NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2 "Filter updates to/from this neighbor\n"
					       "IP Access-list name\n"
					       "Filter incoming updates\n"
					       "Filter outgoing updates\n",
	CMD_ATTR_YANG | CMD_ATTR_HIDDEN);

ALIAS_ATTR(
	neighbor_filter_list_yang, neighbor_filter_list_yang_hidden_cmd,
	"[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor filter-list AS_PATH_FILTER_NAME$name <in|out>$dir",
	NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2 "Establish BGP filters\n"
					       "AS path access-list name\n"
					       "Filter incoming routes\n"
					       "Filter outgoing routes\n",
	CMD_ATTR_YANG | CMD_ATTR_HIDDEN);

ALIAS_ATTR(neighbor_route_map_yang, neighbor_route_map_yang_hidden_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor route-map RMAP_NAME$name <in|out>$dir",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2 "Apply route map to neighbor\n"
						  "Name of route map\n"
						  "Apply map to incoming routes\n"
						  "Apply map to outbound routes\n",
	   CMD_ATTR_YANG | CMD_ATTR_HIDDEN);

ALIAS_ATTR(neighbor_unsuppress_map_yang, neighbor_unsuppress_map_yang_hidden_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor unsuppress-map RMAP_NAME$name",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Route-map to selectively unsuppress suppressed routes\n"
	   "Name of route map\n",
	   CMD_ATTR_YANG | CMD_ATTR_HIDDEN);

ALIAS_ATTR(
	neighbor_allowas_in_yang, neighbor_allowas_in_yang_hidden_cmd,
	"[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor allowas-in [route-map ![RMAP_NAME$rmap_name]] [<(1-10)$allow_num|origin$origin_kw>]",
	NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	"Accept as-path with my AS present in it\n"
	"Filter routes using route-map\n"
	"Name of route-map\n"
	"Number of occurrences of AS number\n"
	"Only accept my AS in the as-path if the route was originated in my AS\n",
	CMD_ATTR_YANG | CMD_ATTR_HIDDEN);

ALIAS_ATTR(
	neighbor_default_originate_yang, neighbor_default_originate_yang_hidden_cmd,
	"[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor default-originate [route-map RMAP_NAME$rmap]",
	NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	"Originate default route to this neighbor\n"
	"Route-map to specify criteria to originate default\n"
	"route-map name\n",
	CMD_ATTR_YANG | CMD_ATTR_HIDDEN);

ALIAS_ATTR(neighbor_weight_yang, neighbor_weight_yang_hidden_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor weight [(0-65535)$weight]",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Set default weight for routes from this neighbor\n"
	   "default weight\n",
	   CMD_ATTR_YANG | CMD_ATTR_HIDDEN);

ALIAS_ATTR(
	neighbor_send_community_yang, neighbor_send_community_yang_hidden_cmd,
	"[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor send-community [<both|all|extended|standard|large>$type]",
	NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	"Send Community attribute to this neighbor\n"
	"Send Standard and Extended Community attributes\n"
	"Send Standard, Large and Extended Community attributes\n"
	"Send Extended Community attributes\n"
	"Send Standard Community attributes\n"
	"Send Large Community attributes\n",
	CMD_ATTR_YANG | CMD_ATTR_HIDDEN);

ALIAS_ATTR(neighbor_send_community_rpki_yang, neighbor_send_community_rpki_yang_hidden_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor send-community extended rpki",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2 "Send Community attribute to this neighbor\n"
						  "Send Extended Community attributes\n"
						  "Send RPKI Extended Community attributes\n",
	   CMD_ATTR_YANG | CMD_ATTR_HIDDEN);

ALIAS_ATTR(neighbor_as_override_yang, neighbor_as_override_yang_hidden_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor as-override",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Override ASNs in outbound updates if aspath equals remote-as\n",
	   CMD_ATTR_YANG | CMD_ATTR_HIDDEN);

ALIAS_ATTR(
	neighbor_remove_private_as_yang, neighbor_remove_private_as_yang_hidden_cmd,
	"[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor remove-private-AS [all$all] [replace-AS$replace]",
	NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	"Remove private ASNs in outbound updates\n"
	"Apply to all AS numbers\n"
	"Replace private ASNs with our ASN in outbound updates\n",
	CMD_ATTR_YANG | CMD_ATTR_HIDDEN);

ALIAS_ATTR(neighbor_route_reflector_client_yang, neighbor_route_reflector_client_yang_hidden_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor route-reflector-client",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Configure a neighbor as Route Reflector client\n",
	   CMD_ATTR_YANG | CMD_ATTR_HIDDEN);

ALIAS_ATTR(neighbor_route_server_client_yang, neighbor_route_server_client_yang_hidden_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor route-server-client",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2 "Configure a neighbor as Route Server client\n",
	   CMD_ATTR_YANG | CMD_ATTR_HIDDEN);

ALIAS_ATTR(neighbor_activate_yang, neighbor_activate_yang_hidden_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor activate",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2 "Enable the Address Family for this Neighbor\n",
	   CMD_ATTR_YANG | CMD_ATTR_HIDDEN);

ALIAS_ATTR(neighbor_soft_reconfiguration_yang, neighbor_soft_reconfiguration_yang_hidden_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor soft-reconfiguration inbound",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Per neighbor soft reconfiguration\n"
	   "Allow inbound soft reconfiguration for this neighbor\n",
	   CMD_ATTR_YANG | CMD_ATTR_HIDDEN);

ALIAS_ATTR(neighbor_nexthop_self_yang, neighbor_nexthop_self_yang_hidden_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor next-hop-self [<force|all>$force]",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Disable the next hop calculation for this neighbor\n"
	   "Set the next hop to self for reflected routes\n"
	   "Set the next hop to self for reflected routes\n",
	   CMD_ATTR_YANG | CMD_ATTR_HIDDEN);

ALIAS_ATTR(
	neighbor_attr_unchanged_yang, neighbor_attr_unchanged_yang_hidden_cmd,
	"[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor attribute-unchanged [{as-path$aspath|next-hop$nexthop|med$med}]",
	NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	"BGP attribute is propagated unchanged to this neighbor\n"
	"As-path attribute\n"
	"Nexthop attribute\n"
	"Med attribute\n",
	CMD_ATTR_YANG | CMD_ATTR_HIDDEN);

ALIAS_ATTR(
	neighbor_dampening_yang, neighbor_dampening_yang_hidden_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor dampening [(1-45)$half [(1-20000)$reuse (1-20000)$suppress (1-255)$max]]",
	NEIGHBOR_STR NEIGHBOR_ADDR_STR2 "Enable neighbor route-flap dampening\n"
					       "Half-life time for the penalty\n"
					       "Value to start reusing a route\n"
					       "Value to start suppressing a route\n"
					       "Maximum duration to suppress a stable route\n",
	CMD_ATTR_YANG | CMD_ATTR_HIDDEN);

ALIAS_ATTR(no_neighbor_dampening_yang, no_neighbor_dampening_yang_hidden_cmd,
	   "no neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor dampening [HALF [REUSE SUPPRESS MAX]]",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	   "Enable neighbor route-flap dampening\n"
	   "Half-life time for the penalty\n"
	   "Value to start reusing a route\n"
	   "Value to start suppressing a route\n"
	   "Maximum duration to suppress a stable route\n",
	   CMD_ATTR_YANG | CMD_ATTR_HIDDEN);

ALIAS_ATTR(neighbor_set_peer_group_yang, neighbor_set_peer_group_yang_hidden_cmd,
	   "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor peer-group PGNAME$pgname",
	   NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2 "Member of the peer-group\n"
						  "Peer-group name\n",
	   CMD_ATTR_YANG | CMD_ATTR_HIDDEN);

static void bgp_cli_install_af_neighbor(void)
{
	install_element(BGP_IPV4_NODE, &neighbor_activate_yang_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_soft_reconfiguration_yang_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_activate_yang_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_soft_reconfiguration_yang_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_activate_yang_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_soft_reconfiguration_yang_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_activate_yang_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_soft_reconfiguration_yang_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_activate_yang_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_soft_reconfiguration_yang_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_activate_yang_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_soft_reconfiguration_yang_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_activate_yang_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_soft_reconfiguration_yang_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_activate_yang_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_soft_reconfiguration_yang_cmd);
	install_element(BGP_FLOWSPECV4_NODE, &neighbor_activate_yang_cmd);
	install_element(BGP_FLOWSPECV4_NODE, &neighbor_soft_reconfiguration_yang_cmd);
	install_element(BGP_FLOWSPECV6_NODE, &neighbor_activate_yang_cmd);
	install_element(BGP_FLOWSPECV6_NODE, &neighbor_soft_reconfiguration_yang_cmd);
	install_element(BGP_EVPN_NODE, &neighbor_activate_yang_cmd);
	install_element(BGP_EVPN_NODE, &neighbor_soft_reconfiguration_yang_cmd);
	/* Link-state / unreachability: activate only (no soft-reconfiguration). */
	install_element(BGP_LS_NODE, &neighbor_activate_yang_cmd);
	install_element(BGP_IPV4U_NODE, &neighbor_activate_yang_cmd);
	install_element(BGP_IPV6U_NODE, &neighbor_activate_yang_cmd);

	/* Hidden at BGP_NODE: defaults to ipv4-unicast like classic. */
	install_element(BGP_NODE, &neighbor_activate_yang_hidden_cmd);
	install_element(BGP_NODE, &neighbor_soft_reconfiguration_yang_hidden_cmd);

	/* nexthop-self / attr-unchanged: not on flowspec */
	install_element(BGP_IPV4_NODE, &neighbor_nexthop_self_yang_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_attr_unchanged_yang_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_nexthop_self_yang_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_attr_unchanged_yang_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_nexthop_self_yang_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_attr_unchanged_yang_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_nexthop_self_yang_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_attr_unchanged_yang_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_nexthop_self_yang_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_attr_unchanged_yang_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_nexthop_self_yang_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_attr_unchanged_yang_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_nexthop_self_yang_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_attr_unchanged_yang_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_nexthop_self_yang_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_attr_unchanged_yang_cmd);
	install_element(BGP_EVPN_NODE, &neighbor_nexthop_self_evpn_yang_cmd);
	install_element(BGP_EVPN_NODE, &neighbor_attr_unchanged_yang_cmd);
	install_element(BGP_FLOWSPECV4_NODE, &neighbor_attr_unchanged_yang_cmd);
	install_element(BGP_FLOWSPECV6_NODE, &neighbor_attr_unchanged_yang_cmd);

	install_element(BGP_NODE, &neighbor_nexthop_self_yang_hidden_cmd);
	install_element(BGP_NODE, &neighbor_attr_unchanged_yang_hidden_cmd);

	/* neighbor dampening: unicast/multicast/labeled (+ BGP_NODE hidden) */
	install_element(BGP_IPV4_NODE, &neighbor_dampening_yang_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_dampening_yang_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_dampening_yang_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_dampening_yang_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_dampening_yang_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_dampening_yang_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_dampening_yang_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_dampening_yang_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_dampening_yang_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_dampening_yang_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_dampening_yang_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_dampening_yang_cmd);
	install_element(BGP_NODE, &neighbor_dampening_yang_hidden_cmd);
	install_element(BGP_NODE, &no_neighbor_dampening_yang_hidden_cmd);

	install_element(BGP_IPV4_NODE, &neighbor_encap_srv6_yang_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_encap_srv6_yang_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_encapsulation_srv6_or_mpls_yang_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_encapsulation_srv6_or_mpls_yang_cmd);

	/* as-override / remove-private-AS: unicast-family set */
	install_element(BGP_IPV4_NODE, &neighbor_as_override_yang_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_remove_private_as_yang_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_as_override_yang_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_remove_private_as_yang_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_as_override_yang_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_remove_private_as_yang_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_as_override_yang_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_remove_private_as_yang_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_as_override_yang_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_remove_private_as_yang_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_as_override_yang_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_remove_private_as_yang_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_as_override_yang_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_remove_private_as_yang_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_as_override_yang_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_remove_private_as_yang_cmd);
	install_element(BGP_NODE, &neighbor_as_override_yang_hidden_cmd);
	install_element(BGP_NODE, &neighbor_remove_private_as_yang_hidden_cmd);

	/* RR / RS clients: include EVPN + flowspec */
	install_element(BGP_IPV4_NODE, &neighbor_route_reflector_client_yang_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_route_server_client_yang_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_route_reflector_client_yang_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_route_server_client_yang_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_route_reflector_client_yang_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_route_server_client_yang_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_route_reflector_client_yang_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_route_server_client_yang_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_route_reflector_client_yang_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_route_server_client_yang_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_route_reflector_client_yang_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_route_server_client_yang_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_route_reflector_client_yang_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_route_server_client_yang_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_route_reflector_client_yang_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_route_server_client_yang_cmd);
	install_element(BGP_EVPN_NODE, &neighbor_route_reflector_client_yang_cmd);
	install_element(BGP_EVPN_NODE, &neighbor_route_server_client_yang_cmd);
	install_element(BGP_FLOWSPECV4_NODE, &neighbor_route_reflector_client_yang_cmd);
	install_element(BGP_FLOWSPECV4_NODE, &neighbor_route_server_client_yang_cmd);
	install_element(BGP_FLOWSPECV6_NODE, &neighbor_route_reflector_client_yang_cmd);
	install_element(BGP_FLOWSPECV6_NODE, &neighbor_route_server_client_yang_cmd);
	install_element(BGP_NODE, &neighbor_route_reflector_client_yang_hidden_cmd);
	install_element(BGP_NODE, &neighbor_route_server_client_yang_hidden_cmd);

	/* weight / send-community */
	install_element(BGP_IPV4_NODE, &neighbor_weight_yang_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_send_community_yang_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_send_community_rpki_yang_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_weight_yang_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_send_community_yang_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_send_community_rpki_yang_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_weight_yang_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_send_community_yang_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_send_community_rpki_yang_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_weight_yang_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_send_community_yang_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_send_community_rpki_yang_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_weight_yang_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_send_community_yang_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_send_community_rpki_yang_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_weight_yang_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_send_community_yang_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_send_community_rpki_yang_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_weight_yang_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_send_community_yang_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_send_community_rpki_yang_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_weight_yang_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_send_community_yang_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_send_community_rpki_yang_cmd);
	install_element(BGP_NODE, &neighbor_weight_yang_hidden_cmd);
	install_element(BGP_NODE, &neighbor_send_community_yang_hidden_cmd);
	install_element(BGP_NODE, &neighbor_send_community_rpki_yang_hidden_cmd);

	/* default-originate: unicast/mcast/labeled only */
	install_element(BGP_IPV4_NODE, &neighbor_default_originate_yang_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_default_originate_yang_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_default_originate_yang_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_default_originate_yang_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_default_originate_yang_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_default_originate_yang_cmd);
	install_element(BGP_NODE, &neighbor_default_originate_yang_hidden_cmd);

	/* allowas-in: as_nodes + EVPN (UPA stays classic) */
	install_element(BGP_IPV4_NODE, &neighbor_allowas_in_yang_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_allowas_in_yang_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_allowas_in_yang_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_allowas_in_yang_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_allowas_in_yang_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_allowas_in_yang_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_allowas_in_yang_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_allowas_in_yang_cmd);
	install_element(BGP_EVPN_NODE, &neighbor_allowas_in_yang_cmd);
	install_element(BGP_IPV4U_NODE, &neighbor_allowas_in_yang_cmd);
	install_element(BGP_IPV6U_NODE, &neighbor_allowas_in_yang_cmd);
	install_element(BGP_NODE, &neighbor_allowas_in_yang_hidden_cmd);

	/* filter policy */
	install_element(BGP_IPV4_NODE, &neighbor_distribute_list_yang_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_prefix_list_yang_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_filter_list_yang_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_route_map_yang_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_unsuppress_map_yang_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_distribute_list_yang_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_prefix_list_yang_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_filter_list_yang_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_route_map_yang_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_unsuppress_map_yang_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_distribute_list_yang_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_prefix_list_yang_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_filter_list_yang_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_route_map_yang_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_unsuppress_map_yang_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_distribute_list_yang_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_prefix_list_yang_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_filter_list_yang_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_route_map_yang_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_unsuppress_map_yang_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_distribute_list_yang_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_prefix_list_yang_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_filter_list_yang_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_route_map_yang_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_unsuppress_map_yang_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_distribute_list_yang_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_prefix_list_yang_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_filter_list_yang_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_route_map_yang_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_unsuppress_map_yang_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_distribute_list_yang_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_prefix_list_yang_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_filter_list_yang_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_route_map_yang_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_unsuppress_map_yang_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_distribute_list_yang_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_prefix_list_yang_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_filter_list_yang_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_route_map_yang_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_unsuppress_map_yang_cmd);
	install_element(BGP_FLOWSPECV4_NODE, &neighbor_prefix_list_yang_cmd);
	install_element(BGP_FLOWSPECV4_NODE, &neighbor_filter_list_yang_cmd);
	install_element(BGP_FLOWSPECV4_NODE, &neighbor_route_map_yang_cmd);
	install_element(BGP_FLOWSPECV6_NODE, &neighbor_prefix_list_yang_cmd);
	install_element(BGP_FLOWSPECV6_NODE, &neighbor_filter_list_yang_cmd);
	install_element(BGP_FLOWSPECV6_NODE, &neighbor_route_map_yang_cmd);
	install_element(BGP_EVPN_NODE, &neighbor_route_map_yang_cmd);
	install_element(BGP_LS_NODE, &neighbor_route_map_yang_cmd);
	install_element(BGP_IPV4U_NODE, &neighbor_route_map_yang_cmd);
	install_element(BGP_IPV6U_NODE, &neighbor_route_map_yang_cmd);

	install_element(BGP_NODE, &neighbor_distribute_list_yang_hidden_cmd);
	install_element(BGP_NODE, &neighbor_prefix_list_yang_hidden_cmd);
	install_element(BGP_NODE, &neighbor_filter_list_yang_hidden_cmd);
	install_element(BGP_NODE, &neighbor_route_map_yang_hidden_cmd);
	install_element(BGP_NODE, &neighbor_unsuppress_map_yang_hidden_cmd);

	/* maximum-prefix / addpath */
	install_element(BGP_IPV4_NODE, &neighbor_maximum_prefix_yang_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_maximum_prefix_yang_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_maximum_prefix_out_yang_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_addpath_tx_yang_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_addpath_tx_best_selected_yang_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_disable_addpath_rx_yang_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_addpath_rx_paths_limit_yang_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_maximum_prefix_yang_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_maximum_prefix_yang_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_maximum_prefix_out_yang_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_addpath_tx_yang_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_addpath_tx_best_selected_yang_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_disable_addpath_rx_yang_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_addpath_rx_paths_limit_yang_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_maximum_prefix_yang_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_maximum_prefix_yang_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_maximum_prefix_out_yang_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_addpath_tx_yang_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_addpath_tx_best_selected_yang_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_disable_addpath_rx_yang_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_addpath_rx_paths_limit_yang_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_maximum_prefix_yang_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_maximum_prefix_yang_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_maximum_prefix_out_yang_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_addpath_tx_yang_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_addpath_tx_best_selected_yang_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_disable_addpath_rx_yang_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_addpath_rx_paths_limit_yang_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_maximum_prefix_yang_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_maximum_prefix_yang_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_maximum_prefix_out_yang_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_addpath_tx_yang_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_addpath_tx_best_selected_yang_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_disable_addpath_rx_yang_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_addpath_rx_paths_limit_yang_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_maximum_prefix_yang_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_maximum_prefix_yang_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_maximum_prefix_out_yang_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_addpath_tx_yang_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_addpath_tx_best_selected_yang_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_disable_addpath_rx_yang_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_addpath_rx_paths_limit_yang_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_maximum_prefix_yang_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_maximum_prefix_yang_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_maximum_prefix_out_yang_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_addpath_tx_yang_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_addpath_tx_best_selected_yang_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_disable_addpath_rx_yang_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_addpath_rx_paths_limit_yang_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_maximum_prefix_yang_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_maximum_prefix_yang_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_maximum_prefix_out_yang_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_addpath_tx_yang_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_addpath_tx_best_selected_yang_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_disable_addpath_rx_yang_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_addpath_rx_paths_limit_yang_cmd);
	install_element(BGP_EVPN_NODE, &neighbor_maximum_prefix_yang_cmd);
	install_element(BGP_EVPN_NODE, &no_neighbor_maximum_prefix_yang_cmd);
	install_element(BGP_EVPN_NODE, &neighbor_addpath_tx_yang_cmd);
	install_element(BGP_EVPN_NODE, &neighbor_addpath_tx_best_selected_yang_cmd);
	install_element(BGP_EVPN_NODE, &neighbor_disable_addpath_rx_yang_cmd);
	install_element(BGP_EVPN_NODE, &neighbor_addpath_rx_paths_limit_yang_cmd);
	install_element(BGP_IPV4U_NODE, &neighbor_maximum_prefix_yang_cmd);
	install_element(BGP_IPV4U_NODE, &no_neighbor_maximum_prefix_yang_cmd);
	install_element(BGP_IPV4U_NODE, &neighbor_maximum_prefix_out_yang_cmd);
	install_element(BGP_IPV6U_NODE, &neighbor_maximum_prefix_yang_cmd);
	install_element(BGP_IPV6U_NODE, &no_neighbor_maximum_prefix_yang_cmd);
	install_element(BGP_IPV6U_NODE, &neighbor_maximum_prefix_out_yang_cmd);
	/* maximum-prefix-out also on as_nodes without EVPN already covered */
	install_element(BGP_NODE, &neighbor_maximum_prefix_yang_hidden_cmd);
	install_element(BGP_NODE, &no_neighbor_maximum_prefix_yang_hidden_cmd);
	install_element(BGP_NODE, &neighbor_maximum_prefix_out_yang_hidden_cmd);
	install_element(BGP_NODE, &neighbor_addpath_tx_yang_hidden_cmd);
	install_element(BGP_NODE, &neighbor_addpath_rx_paths_limit_yang_hidden_cmd);

	/* advertise-map / soo / upa / orf / accept-own */
	install_element(BGP_IPV4_NODE, &neighbor_advertise_map_yang_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_soo_yang_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_advertise_map_yang_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_soo_yang_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_advertise_map_yang_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_soo_yang_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_advertise_map_yang_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_soo_yang_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_advertise_map_yang_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_soo_yang_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_advertise_map_yang_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_soo_yang_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_advertise_map_yang_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_soo_yang_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_advertise_map_yang_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_soo_yang_cmd);
	install_element(BGP_EVPN_NODE, &neighbor_soo_yang_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_accept_own_yang_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_accept_own_yang_cmd);

	/* upa + orf: unicast/mcast/labeled only (not VPN) */
	install_element(BGP_IPV4_NODE, &neighbor_upa_yang_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_capability_orf_yang_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_upa_yang_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_capability_orf_yang_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_upa_yang_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_capability_orf_yang_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_upa_yang_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_capability_orf_yang_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_upa_yang_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_capability_orf_yang_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_upa_yang_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_capability_orf_yang_cmd);

	install_element(BGP_NODE, &neighbor_advertise_map_yang_hidden_cmd);
	install_element(BGP_NODE, &neighbor_upa_yang_hidden_cmd);
	install_element(BGP_NODE, &neighbor_capability_orf_yang_hidden_cmd);

	/* nexthop-local unchanged: IPv6 unicast only */
	install_element(BGP_IPV6_NODE, &neighbor_nexthop_local_unchanged_yang_cmd);
}


ALIAS_ATTR(vpn_network_yang, vpn_network_v4_yang_cmd,
	   "[no] network A.B.C.D/M$prefix4 rd ASN:NN_OR_IP-ADDRESS:NN$rd <tag|label> (0-1048575)$label [route-map RMAP_NAME$map_name]",
	   NO_STR
	   "Specify a network to announce via BGP\n"
	   "IPv4 prefix\n"
	   "Specify Route Distinguisher\n"
	   "VPN Route Distinguisher\n"
	   "VPN NLRI label (tag)\n"
	   "VPN NLRI label (tag)\n"
	   "Label value\n"
	   "Route map\n"
	   "Route map name\n",
	   CMD_ATTR_YANG);

ALIAS_ATTR(vpn_network_yang, vpn_network_v6_yang_cmd,
	   "[no] network X:X::X:X/M$prefix6 rd ASN:NN_OR_IP-ADDRESS:NN$rd <tag|label> (0-1048575)$label [route-map RMAP_NAME$map_name]",
	   NO_STR
	   "Specify a network to announce via BGP\n"
	   "IPv6 prefix\n"
	   "Specify Route Distinguisher\n"
	   "VPN Route Distinguisher\n"
	   "VPN NLRI label (tag)\n"
	   "VPN NLRI label (tag)\n"
	   "Label value\n"
	   "Route map\n"
	   "Route map name\n",
	   CMD_ATTR_YANG);

void bgp_cli_init(void)
{
	install_element(CONFIG_NODE, &router_bgp_yang_cmd);
	install_element(CONFIG_NODE, &no_router_bgp_yang_cmd);

	install_element(INTERFACE_NODE, &mpls_bgp_forwarding_yang_cmd);
	install_element(INTERFACE_NODE, &mpls_bgp_l3vpn_multi_domain_switching_yang_cmd);

	/* address-family enter — creates global afi-safi list entry */
	install_element(BGP_NODE, &address_family_ipv4_yang_cmd);
	install_element(BGP_NODE, &address_family_ipv6_yang_cmd);
#ifdef KEEP_OLD_VPN_COMMANDS
	install_element(BGP_NODE, &address_family_vpnv4_yang_cmd);
	install_element(BGP_NODE, &address_family_vpnv6_yang_cmd);
#endif /* KEEP_OLD_VPN_COMMANDS */
	install_element(BGP_NODE, &address_family_evpn_yang_cmd);
	install_element(BGP_NODE, &address_family_link_state_yang_cmd);

	install_element(BGP_NODE, &bgp_segment_routing_srv6_yang_cmd);
	install_element(BGP_NODE, &no_bgp_segment_routing_srv6_yang_cmd);
	install_element(BGP_SRV6_NODE, &bgp_srv6_locator_yang_cmd);
	install_element(BGP_SRV6_NODE, &no_bgp_srv6_locator_yang_cmd);
	install_element(BGP_SRV6_NODE, &bgp_srv6_only_yang_cmd);
	install_element(BGP_SRV6_NODE, &bgp_srv6_encap_behavior_yang_cmd);
	install_element(BGP_NODE, &bgp_sid_vpn_export_yang_cmd);
	install_element(BGP_LS_NODE, &bgp_ls_distribute_bgp_fabric_yang_cmd);
	install_element(BGP_FLOWSPECV4_NODE, &bgp_fs_local_install_yang_cmd);
	install_element(BGP_FLOWSPECV6_NODE, &bgp_fs_local_install_yang_cmd);

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
	install_element(BGP_NODE, &bgp_rmap_delay_timer_yang_cmd);
	install_element(BGP_NODE, &bgp_advertisement_delay_yang_cmd);
	install_element(BGP_NODE, &no_bgp_advertisement_delay_yang_cmd);

	install_element(BGP_NODE, &bgp_listen_limit_yang_cmd);
	install_element(BGP_NODE, &no_bgp_listen_limit_yang_cmd);
	install_element(BGP_NODE, &bgp_listen_range_yang_cmd);
	install_element(BGP_NODE, &bgp_condadv_period_yang_cmd);
	install_element(BGP_NODE, &bgp_def_originate_eval_yang_cmd);
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
	install_element(BGP_NODE, &bgp_default_originate_setonly_yang_cmd);
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
	install_element(BGP_NODE, &neighbor_ls_local_link_id_yang_cmd);
	install_element(BGP_NODE, &neighbor_ls_remote_link_id_yang_cmd);
	install_element(BGP_NODE, &neighbor_passive_yang_cmd);
	install_element(BGP_NODE, &neighbor_solo_yang_cmd);
	install_element(BGP_NODE, &neighbor_shutdown_yang_cmd);
	install_element(BGP_NODE, &neighbor_shutdown_msg_yang_cmd);
	install_element(BGP_NODE, &no_neighbor_shutdown_msg_yang_cmd);
	install_element(BGP_NODE, &neighbor_shutdown_rtt_yang_cmd);
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
	install_element(BGP_NODE, &neighbor_extended_link_bw_yang_cmd);
	install_element(BGP_NODE, &neighbor_disable_link_bw_ieee_yang_cmd);
	install_element(BGP_NODE, &neighbor_extended_opt_params_yang_cmd);
	install_element(BGP_NODE, &neighbor_send_nhc_yang_cmd);
	install_element(BGP_NODE, &neighbor_as_loop_detection_yang_cmd);
	install_element(BGP_NODE, &neighbor_oad_yang_cmd);
	install_element(BGP_NODE, &neighbor_graceful_shutdown_yang_cmd);
	install_element(BGP_NODE, &neighbor_set_peer_group_yang_cmd);
	install_element(BGP_NODE, &neighbor_port_yang_cmd);
	install_element(BGP_NODE, &neighbor_local_interface_yang_cmd);

	/* Hidden peer-group membership under AF nodes (classic parity). */
	install_element(BGP_IPV4_NODE, &neighbor_set_peer_group_yang_hidden_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_set_peer_group_yang_hidden_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_set_peer_group_yang_hidden_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_set_peer_group_yang_hidden_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_set_peer_group_yang_hidden_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_set_peer_group_yang_hidden_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_set_peer_group_yang_hidden_cmd);
	install_element(BGP_FLOWSPECV4_NODE, &neighbor_set_peer_group_yang_hidden_cmd);
	install_element(BGP_FLOWSPECV6_NODE, &neighbor_set_peer_group_yang_hidden_cmd);

	/* network statements: unicast/multicast/labeled-unicast */
	install_element(BGP_IPV4_NODE, &bgp_network_yang_cmd);
	install_element(BGP_IPV4M_NODE, &bgp_network_yang_cmd);
	install_element(BGP_IPV4L_NODE, &bgp_network_yang_cmd);
	install_element(BGP_IPV6_NODE, &ipv6_bgp_network_yang_cmd);
	install_element(BGP_IPV6M_NODE, &ipv6_bgp_network_yang_cmd);
	install_element(BGP_IPV6L_NODE, &ipv6_bgp_network_yang_cmd);
	install_element(BGP_NODE, &bgp_network_yang_hidden_cmd);

	/* aggregate-address: unicast/multicast/labeled-unicast */
	install_element(BGP_IPV4_NODE, &aggregate_addressv4_yang_cmd);
	install_element(BGP_IPV4M_NODE, &aggregate_addressv4_yang_cmd);
	install_element(BGP_IPV4L_NODE, &aggregate_addressv4_yang_cmd);
	install_element(BGP_IPV6_NODE, &aggregate_addressv6_yang_cmd);
	install_element(BGP_IPV6L_NODE, &aggregate_addressv6_yang_cmd);
	install_element(BGP_NODE, &aggregate_addressv4_yang_hidden_cmd);

	/* maximum-paths: unicast + labeled */
	install_element(BGP_IPV4_NODE, &bgp_maxpaths_yang_cmd);
	install_element(BGP_IPV4_NODE, &bgp_maxpaths_ibgp_yang_cmd);
	install_element(BGP_IPV6_NODE, &bgp_maxpaths_yang_cmd);
	install_element(BGP_IPV6_NODE, &bgp_maxpaths_ibgp_yang_cmd);
	install_element(BGP_IPV4L_NODE, &bgp_maxpaths_yang_cmd);
	install_element(BGP_IPV4L_NODE, &bgp_maxpaths_ibgp_yang_cmd);
	install_element(BGP_IPV6L_NODE, &bgp_maxpaths_yang_cmd);
	install_element(BGP_IPV6L_NODE, &bgp_maxpaths_ibgp_yang_cmd);
	install_element(BGP_NODE, &bgp_maxpaths_yang_hidden_cmd);
	install_element(BGP_NODE, &bgp_maxpaths_ibgp_yang_hidden_cmd);

	/* redistribute: ipv4/ipv6 unicast */
	install_element(BGP_IPV4_NODE, &bgp_redistribute_ipv4_yang_cmd);
	install_element(BGP_IPV4_NODE, &bgp_redistribute_ipv4_instance_yang_cmd);
	install_element(BGP_IPV6_NODE, &bgp_redistribute_ipv6_yang_cmd);
	install_element(BGP_IPV6_NODE, &bgp_redistribute_ipv6_table_yang_cmd);
	install_element(BGP_NODE, &bgp_redistribute_ipv4_yang_hidden_cmd);
	install_element(BGP_NODE, &bgp_redistribute_ipv4_instance_yang_hidden_cmd);

	/* distance: ipv4/ipv6 unicast + multicast */
	install_element(BGP_IPV4_NODE, &bgp_distance_yang_cmd);
	install_element(BGP_IPV4_NODE, &bgp_distance_source_yang_cmd);
	install_element(BGP_IPV4M_NODE, &bgp_distance_yang_cmd);
	install_element(BGP_IPV4M_NODE, &bgp_distance_source_yang_cmd);
	install_element(BGP_IPV6_NODE, &bgp_distance_yang_cmd);
	install_element(BGP_IPV6_NODE, &bgp_distance_source_v6_yang_cmd);
	install_element(BGP_IPV6M_NODE, &bgp_distance_yang_cmd);
	install_element(BGP_IPV6M_NODE, &bgp_distance_source_v6_yang_cmd);
	install_element(BGP_NODE, &bgp_distance_yang_hidden_cmd);
	install_element(BGP_NODE, &bgp_distance_source_yang_hidden_cmd);

	/* table-map: unicast + ipv4 multicast */
	install_element(BGP_IPV4_NODE, &bgp_table_map_yang_cmd);
	install_element(BGP_IPV4M_NODE, &bgp_table_map_yang_cmd);
	install_element(BGP_IPV6_NODE, &bgp_table_map_yang_cmd);
	install_element(BGP_NODE, &bgp_table_map_yang_hidden_cmd);

	/* bgp dampening: unicast/multicast/labeled */
	install_element(BGP_IPV4_NODE, &bgp_dampening_yang_cmd);
	install_element(BGP_IPV6_NODE, &bgp_dampening_yang_cmd);
	install_element(BGP_IPV4M_NODE, &bgp_dampening_yang_cmd);
	install_element(BGP_IPV6M_NODE, &bgp_dampening_yang_cmd);
	install_element(BGP_IPV4L_NODE, &bgp_dampening_yang_cmd);
	install_element(BGP_IPV6L_NODE, &bgp_dampening_yang_cmd);
	install_element(BGP_NODE, &bgp_dampening_yang_hidden_cmd);

	/* AF-level UPA (unicast) */
	install_element(BGP_IPV4_NODE, &upa_originate_all_yang_cmd);
	install_element(BGP_IPV4_NODE, &upa_max_routes_yang_cmd);
	install_element(BGP_IPV4_NODE, &upa_drop_yang_cmd);
	install_element(BGP_IPV6_NODE, &upa_originate_all_yang_cmd);
	install_element(BGP_IPV6_NODE, &upa_max_routes_yang_cmd);
	install_element(BGP_IPV6_NODE, &upa_drop_yang_cmd);

	install_element(BGP_IPV6_NODE, &bgp_af_nexthop_prefer_global_yang_cmd);
	install_element(BGP_IPV6M_NODE, &bgp_af_nexthop_prefer_global_yang_cmd);
	install_element(BGP_IPV6L_NODE, &bgp_af_nexthop_prefer_global_yang_cmd);

	/* EVPN AF global knobs */
	install_element(BGP_EVPN_NODE, &bgp_evpn_advertise_all_vni_yang_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_autort_rfc8365_yang_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_advertise_default_gw_yang_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_advertise_svi_ip_yang_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_resolve_overlay_yang_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_flooding_yang_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_macvrf_soo_yang_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_dad_yang_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_use_es_l3nhg_yang_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_disable_ead_evi_rx_yang_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_disable_ead_evi_tx_yang_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_ead_es_frag_yang_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_default_originate_yang_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_advertise_type5_yang_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_advertise_pip_yang_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_ead_es_rt_yang_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_vrf_rd_yang_cmd);
	install_element(BGP_NODE, &no_bgp_evpn_vrf_rd_without_val_yang_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_vrf_rt_yang_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_vrf_rt_auto_yang_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_vrf_auto_rt_yang_cmd);
	install_element(BGP_EVPN_NODE, &no_bgp_evpn_vrf_auto_rt_yang_cmd);
	install_element(BGP_EVPN_NODE, &bgp_evpn_vni_yang_cmd);
	install_element(BGP_EVPN_NODE, &no_bgp_evpn_vni_yang_cmd);
	install_element(BGP_EVPN_VNI_NODE, &exit_vni_yang_cmd);
	install_element(BGP_EVPN_VNI_NODE, &bgp_evpn_vni_rd_yang_cmd);
	install_element(BGP_EVPN_VNI_NODE, &bgp_evpn_vni_rt_yang_cmd);
	install_element(BGP_EVPN_VNI_NODE, &no_bgp_evpn_vni_rt_without_val_yang_cmd);
	install_element(BGP_EVPN_VNI_NODE, &bgp_evpn_vni_auto_rt_yang_cmd);
	install_element(BGP_EVPN_VNI_NODE, &no_bgp_evpn_vni_auto_rt_yang_cmd);
	install_element(BGP_EVPN_VNI_NODE, &bgp_evpn_vni_advertise_default_gw_yang_cmd);
	install_element(BGP_EVPN_VNI_NODE, &bgp_evpn_vni_advertise_svi_ip_yang_cmd);
	install_element(BGP_EVPN_VNI_NODE, &bgp_evpn_vni_advertise_subnet_yang_cmd);
	install_element(BGP_EVPN_VNI_NODE, &bgp_evpn_vni_flooding_yang_cmd);

	/* Daemon-wide CONFIG_NODE (/frr-bgp:bgp-daemon) */
	install_element(CONFIG_NODE, &bgp_daemon_norib_yang_cmd);
	install_element(CONFIG_NODE, &no_bgp_daemon_norib_yang_cmd);
	install_element(CONFIG_NODE, &bgp_daemon_session_dscp_yang_cmd);
	install_element(CONFIG_NODE, &no_bgp_daemon_session_dscp_yang_cmd);
	install_element(CONFIG_NODE, &bgp_daemon_inq_limit_yang_cmd);
	install_element(CONFIG_NODE, &no_bgp_daemon_inq_limit_yang_cmd);
	install_element(CONFIG_NODE, &bgp_daemon_outq_limit_yang_cmd);
	install_element(CONFIG_NODE, &no_bgp_daemon_outq_limit_yang_cmd);
	install_element(CONFIG_NODE, &bgp_daemon_suppress_fib_yang_cmd);
	install_element(CONFIG_NODE, &bgp_ipv6_auto_ra_yang_cmd);
	install_element(CONFIG_NODE, &bgp_daemon_update_delay_yang_cmd);
	install_element(CONFIG_NODE, &no_bgp_daemon_update_delay_yang_cmd);
	install_element(CONFIG_NODE, &bgp_daemon_advertisement_delay_yang_cmd);
	install_element(CONFIG_NODE, &no_bgp_daemon_advertisement_delay_yang_cmd);
	install_element(CONFIG_NODE, &bgp_daemon_community_alias_yang_cmd);
	install_element(CONFIG_NODE, &bgp_daemon_send_extra_data_yang_cmd);
	install_element(CONFIG_NODE, &bgp_daemon_snmp_traps_rfc4273_yang_cmd);
	install_element(CONFIG_NODE, &bgp_daemon_snmp_traps_bgp4_mibv2_yang_cmd);
	install_element(CONFIG_NODE, &bgp_daemon_snmp_traps_rfc4382_yang_cmd);
	install_element(CONFIG_NODE, &bgp_daemon_rmap_delay_timer_yang_cmd);
	install_element(CONFIG_NODE, &bgp_daemon_graceful_restart_yang_cmd);
	install_element(CONFIG_NODE, &no_bgp_daemon_graceful_restart_yang_cmd);
	install_element(CONFIG_NODE, &bgp_daemon_graceful_restart_disable_yang_cmd);
	install_element(CONFIG_NODE, &no_bgp_daemon_graceful_restart_disable_yang_cmd);
	install_element(CONFIG_NODE, &bgp_daemon_gr_stalepath_time_yang_cmd);
	install_element(CONFIG_NODE, &no_bgp_daemon_gr_stalepath_time_yang_cmd);
	install_element(CONFIG_NODE, &bgp_daemon_gr_restart_time_yang_cmd);
	install_element(CONFIG_NODE, &no_bgp_daemon_gr_restart_time_yang_cmd);
	install_element(CONFIG_NODE, &bgp_daemon_gr_select_defer_time_yang_cmd);
	install_element(CONFIG_NODE, &no_bgp_daemon_gr_select_defer_time_yang_cmd);
	install_element(CONFIG_NODE, &bgp_daemon_gr_rib_stale_time_yang_cmd);
	install_element(CONFIG_NODE, &no_bgp_daemon_gr_rib_stale_time_yang_cmd);
	install_element(CONFIG_NODE, &bgp_daemon_gr_preserve_fw_yang_cmd);
	install_element(CONFIG_NODE, &no_bgp_daemon_gr_preserve_fw_yang_cmd);
	install_element(CONFIG_NODE, &bgp_daemon_graceful_shutdown_yang_cmd);
	install_element(CONFIG_NODE, &no_bgp_daemon_graceful_shutdown_yang_cmd);

	/* AF-level import|export vpn */
	install_element(BGP_IPV4_NODE, &bgp_imexport_vpn_yang_cmd);
	install_element(BGP_IPV6_NODE, &bgp_imexport_vpn_yang_cmd);
	install_element(BGP_IPV4_NODE, &af_route_map_vpn_yang_cmd);
	install_element(BGP_IPV6_NODE, &af_route_map_vpn_yang_cmd);
	install_element(BGP_IPV4_NODE, &af_rd_vpn_export_yang_cmd);
	install_element(BGP_IPV6_NODE, &af_rd_vpn_export_yang_cmd);
	install_element(BGP_IPV4_NODE, &af_label_vpn_export_yang_cmd);
	install_element(BGP_IPV6_NODE, &af_label_vpn_export_yang_cmd);
	install_element(BGP_IPV4_NODE, &af_label_vpn_alloc_mode_yang_cmd);
	install_element(BGP_IPV6_NODE, &af_label_vpn_alloc_mode_yang_cmd);
	install_element(BGP_IPV4_NODE, &af_nexthop_vpn_export_yang_cmd);
	install_element(BGP_IPV6_NODE, &af_nexthop_vpn_export_yang_cmd);
	install_element(BGP_IPV4_NODE, &af_rt_vpn_yang_cmd);
	install_element(BGP_IPV4_NODE, &af_no_rt_vpn_yang_cmd);
	install_element(BGP_IPV6_NODE, &af_rt_vpn_yang_cmd);
	install_element(BGP_IPV6_NODE, &af_no_rt_vpn_yang_cmd);
	install_element(BGP_IPV4_NODE, &bgp_import_vrf_yang_cmd);
	install_element(BGP_IPV6_NODE, &bgp_import_vrf_yang_cmd);
	install_element(BGP_IPV4_NODE, &af_import_vrf_route_map_yang_cmd);
	install_element(BGP_IPV6_NODE, &af_import_vrf_route_map_yang_cmd);
	install_element(BGP_IPV4_NODE, &af_routetarget_redirect_yang_cmd);
	install_element(BGP_IPV6_NODE, &af_routetarget_redirect_yang_cmd);
	install_element(BGP_VPNV4_NODE, &bgp_retain_route_target_yang_cmd);
	install_element(BGP_VPNV6_NODE, &bgp_retain_route_target_yang_cmd);
	install_element(BGP_VPNV4_NODE, &vpn_network_v4_yang_cmd);
	install_element(BGP_VPNV6_NODE, &vpn_network_v6_yang_cmd);

	/* BMP under BGP_NODE (BMP_NODE installs wait for bgp_cli_bmp_init) */
	install_element(BGP_NODE, &bmp_mirror_limit_yang_cmd);
	install_element(BGP_NODE, &bmp_targets_yang_cmd);
	install_element(BGP_NODE, &no_bmp_targets_yang_cmd);

	install_element(BGP_IPV4_NODE, &sid_export_yang_cmd);
	install_element(BGP_IPV6_NODE, &sid_export_yang_cmd);
	install_element(BGP_IPV4_NODE, &af_sid_vpn_export_yang_cmd);
	install_element(BGP_IPV6_NODE, &af_sid_vpn_export_yang_cmd);

	bgp_cli_install_af_neighbor();

	bgp_filter_cli_init();
#ifdef ENABLE_BGP_VNC
	bgp_vnc_cli_init();
#endif
}

/* Called from bgp_bmp_init() after BMP_NODE is installed. */
void bgp_cli_bmp_init(void)
{
	install_element(BMP_NODE, &bmp_mirror_yang_cmd);
	install_element(BMP_NODE, &bmp_stats_yang_cmd);
	install_element(BMP_NODE, &bmp_stats_experimental_yang_cmd);
	install_element(BMP_NODE, &bmp_acl_yang_cmd);
	install_element(BMP_NODE, &bmp_initiation_yang_cmd);
	install_element(BMP_NODE, &no_bmp_initiation_yang_cmd);
	install_element(BMP_NODE, &bmp_listener_yang_cmd);
	install_element(BMP_NODE, &bmp_connect_yang_cmd);
	install_element(BMP_NODE, &bmp_import_vrf_yang_cmd);
	install_element(BMP_NODE, &bmp_monitor_yang_cmd);
}
