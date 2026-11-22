// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP VTY interface.
 * Copyright (C) 1996, 97, 98, 99, 2000 Kunihiro Ishiguro
 */

#include <zebra.h>

#ifdef GNU_LINUX
#include <linux/rtnetlink.h> //RT_TABLE_XXX
#endif

#include "command.h"
#include "lib/json.h"
#include "lib/sockopt.h"
#include "lib_errors.h"
#include "lib/zclient.h"
#include "lib/printfrr.h"
#include "prefix.h"
#include "plist.h"
#include "buffer.h"
#include "linklist.h"
#include "stream.h"
#include "frrevent.h"
#include "log.h"
#include "memory.h"
#include "lib_vty.h"
#include "hash.h"
#include "queue.h"
#include "filter.h"
#include "frrstr.h"
#include "asn.h"
#include "frregex_real.h"

#include "northbound_cli.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_nb.h"
#include "bgpd/bgp_attr_evpn.h"
#include "bgpd/bgp_advertise.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_community_alias.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_lcommunity.h"
#include "bgpd/bgp_damp.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_nht.h"
#include "bgpd/bgp_nexthop.h"
#include "bgpd/bgp_network.h"
#include "bgpd/bgp_open.h"
#include "bgpd/bgp_regex.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_mpath.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_updgrp.h"
#include "bgpd/bgp_bfd.h"
#include "bgpd/bgp_io.h"
#include "bgpd/bgp_evpn.h"
#include "bgpd/bgp_evpn_vty.h"
#include "bgpd/bgp_evpn_mh.h"
#include "bgpd/bgp_addpath.h"
#include "bgpd/bgp_mac.h"
#include "bgpd/bgp_flowspec.h"
#include "bgpd/bgp_conditional_adv.h"
#include "bgpd/bgp_srv6.h"
#include "bgpd/bgp_unreach.h"
#include "bgpd/bgp_ls.h"

extern struct host host;

/* Forward declarations */


/* Show BGP peer's information. */
enum show_type {
	show_all,
	show_peer,
	show_ipv4_all,
	show_ipv6_all,
	show_ipv4_peer,
	show_ipv6_peer
};

static const char *get_afi_safi_vty_str(afi_t afi, safi_t safi)
{
	if (afi == AFI_IP) {
		if (safi == SAFI_UNICAST)
			return "IPv4 Unicast";
		if (safi == SAFI_MULTICAST)
			return "IPv4 Multicast";
		if (safi == SAFI_LABELED_UNICAST)
			return "IPv4 Labeled Unicast";
		if (safi == SAFI_MPLS_VPN)
			return "IPv4 VPN";
		if (safi == SAFI_ENCAP)
			return "IPv4 Encap";
		if (safi == SAFI_FLOWSPEC)
			return "IPv4 Flowspec";
		if (safi == SAFI_UNREACH)
			return "IPv4 Unreachability";
	} else if (afi == AFI_IP6) {
		if (safi == SAFI_UNICAST)
			return "IPv6 Unicast";
		if (safi == SAFI_MULTICAST)
			return "IPv6 Multicast";
		if (safi == SAFI_LABELED_UNICAST)
			return "IPv6 Labeled Unicast";
		if (safi == SAFI_MPLS_VPN)
			return "IPv6 VPN";
		if (safi == SAFI_ENCAP)
			return "IPv6 Encap";
		if (safi == SAFI_FLOWSPEC)
			return "IPv6 Flowspec";
		if (safi == SAFI_UNREACH)
			return "IPv6 Unreachability";
	} else if (afi == AFI_L2VPN) {
		if (safi == SAFI_EVPN)
			return "L2VPN EVPN";
	} else if (afi == AFI_BGP_LS) {
		if (safi == SAFI_BGP_LS)
			return "Link-State Link-State";
	}

	return "Unknown";
}

/*
 * Please note that we have intentionally camelCased
 * the return strings here.  So if you want
 * to use this function, please ensure you
 * are doing this within json output
 */
static const char *get_afi_safi_json_str(afi_t afi, safi_t safi)
{
	if (afi == AFI_IP) {
		if (safi == SAFI_UNICAST)
			return "ipv4Unicast";
		if (safi == SAFI_MULTICAST)
			return "ipv4Multicast";
		if (safi == SAFI_LABELED_UNICAST)
			return "ipv4LabeledUnicast";
		if (safi == SAFI_MPLS_VPN)
			return "ipv4Vpn";
		if (safi == SAFI_ENCAP)
			return "ipv4Encap";
		if (safi == SAFI_FLOWSPEC)
			return "ipv4Flowspec";
		if (safi == SAFI_UNREACH)
			return "ipv4Unreachability";
	} else if (afi == AFI_IP6) {
		if (safi == SAFI_UNICAST)
			return "ipv6Unicast";
		if (safi == SAFI_MULTICAST)
			return "ipv6Multicast";
		if (safi == SAFI_LABELED_UNICAST)
			return "ipv6LabeledUnicast";
		if (safi == SAFI_MPLS_VPN)
			return "ipv6Vpn";
		if (safi == SAFI_ENCAP)
			return "ipv6Encap";
		if (safi == SAFI_FLOWSPEC)
			return "ipv6Flowspec";
		if (safi == SAFI_UNREACH)
			return "ipv6Unreachability";
	} else if (afi == AFI_L2VPN) {
		if (safi == SAFI_EVPN)
			return "l2VpnEvpn";
	} else if (afi == AFI_BGP_LS) {
		if (safi == SAFI_BGP_LS)
			return "linkState";
	}

	return "Unknown";
}

void bgp_srv6_sids_unset(struct bgp *bgp)
{
	struct listnode *node, *nnode;
	struct srv6_locator_chunk *chunk;
	struct bgp_srv6_function *func;
	struct bgp *bgp_vrf;
	struct srv6_sid_ctx ctx = {};

	/* withdraw srv6 unicast and refresh srv6 unicast sid locator */
	if (bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT) {
		if (is_srv6_unicast_enabled(bgp, AFI_IP)) {
			bgp_srv6_unicast_withdraw(bgp, AFI_IP);
			bgp_srv6_unicast_sid_withdraw(bgp, AFI_IP);
			/* locator deleted after this call, free the sid */
			XFREE(MTYPE_BGP_SRV6_SID, bgp->srv6_unicast[AFI_IP].sid);
			srv6_locator_free(bgp->srv6_unicast[AFI_IP].sid_locator);
			bgp->srv6_unicast[AFI_IP].sid_locator = NULL;
		}
		if (is_srv6_unicast_enabled(bgp, AFI_IP6)) {
			bgp_srv6_unicast_withdraw(bgp, AFI_IP6);
			bgp_srv6_unicast_sid_withdraw(bgp, AFI_IP6);
			/* locator deleted after this call, free the sid */
			XFREE(MTYPE_BGP_SRV6_SID, bgp->srv6_unicast[AFI_IP6].sid);
			srv6_locator_free(bgp->srv6_unicast[AFI_IP6].sid_locator);
			bgp->srv6_unicast[AFI_IP6].sid_locator = NULL;
		}
	}

	for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, bgp_vrf)) {
		if (bgp_vrf->inst_type != BGP_INSTANCE_TYPE_VRF)
			continue;

		if (bgp->inst_type == BGP_INSTANCE_TYPE_VRF && bgp_vrf != bgp)
			continue;

		if (bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT && bgp != bgp_vrf &&
		    bgp_vrf->srv6_locator)
			/* bgp_vrf has an active locator, we have to keep it */
			continue;

		if (bgp_vrf->vpn_policy[AFI_IP].tovpn_sid || bgp_vrf->tovpn_sid)
			vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, AFI_IP, bgp_get_default(),
					   bgp_vrf);
		if (bgp_vrf->vpn_policy[AFI_IP6].tovpn_sid || bgp_vrf->tovpn_sid)
			vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, AFI_IP6, bgp_get_default(),
					   bgp_vrf);
	}

	/* refresh chunks */
	for (ALL_LIST_ELEMENTS(bgp->srv6_locator_chunks, node, nnode, chunk)) {
		listnode_delete(bgp->srv6_locator_chunks, chunk);
		srv6_locator_chunk_free(&chunk);
	}

	/* refresh functions */
	for (ALL_LIST_ELEMENTS(bgp->srv6_functions, node, nnode, func)) {
		listnode_delete(bgp->srv6_functions, func);
		srv6_function_free(func);
	}

	/* refresh tovpn_sid */
	for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, bgp_vrf)) {
		if (bgp->inst_type == BGP_INSTANCE_TYPE_VRF && bgp_vrf != bgp)
			continue;

		if (bgp_vrf->inst_type != BGP_INSTANCE_TYPE_VRF)
			/* TODO: accept SRv6 entries on default VRF */
			continue;

		if (bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT && bgp != bgp_vrf &&
		    bgp_vrf->srv6_locator)
			/* bgp_vrf has an active locator, we have to keep it */
			continue;

		ctx.vrf_id = bgp_vrf->vrf_id;

		if (bgp_vrf->vpn_policy[AFI_IP].tovpn_sid) {
			/* release vpnv4 tovpn_sid */
			ctx.behavior = ZEBRA_SEG6_LOCAL_ACTION_END_DT4;
			bgp_zebra_release_srv6_sid(&ctx, bgp_vrf->vpn_policy[AFI_IP]
								 .tovpn_sid_locator->name);
			/* refresh vpnv4 tovpn_sid */
			XFREE(MTYPE_BGP_SRV6_SID, bgp_vrf->vpn_policy[AFI_IP].tovpn_sid);
			UNSET_FLAG(bgp_vrf->vpn_policy[AFI_IP].flags,
				   BGP_VPN_POLICY_TOVPN_SID_FUNC_WIDE);
		}

		if (bgp_vrf->vpn_policy[AFI_IP6].tovpn_sid) {
			/* release vpnv6 tovpn_sid */
			ctx.behavior = ZEBRA_SEG6_LOCAL_ACTION_END_DT6;
			bgp_zebra_release_srv6_sid(&ctx, bgp_vrf->vpn_policy[AFI_IP6]
								 .tovpn_sid_locator->name);
			/* refresh vpnv6 tovpn_sid */
			XFREE(MTYPE_BGP_SRV6_SID, bgp_vrf->vpn_policy[AFI_IP6].tovpn_sid);
			UNSET_FLAG(bgp_vrf->vpn_policy[AFI_IP6].flags,
				   BGP_VPN_POLICY_TOVPN_SID_FUNC_WIDE);
		}

		if (bgp_vrf->tovpn_sid) {
			/* release vpnvx tovpn_sid */
			ctx.behavior = ZEBRA_SEG6_LOCAL_ACTION_END_DT46;
			bgp_zebra_release_srv6_sid(&ctx, bgp_vrf->tovpn_sid_locator->name);
			/* refresh per-vrf tovpn_sid */
			XFREE(MTYPE_BGP_SRV6_SID, bgp_vrf->tovpn_sid);
			UNSET_FLAG(bgp_vrf->vrf_flags, BGP_VRF_TOVPN_SID_FUNC_WIDE);
		}

		/* refresh vpnv4 tovpn_sid_locator */
		srv6_locator_free(bgp_vrf->vpn_policy[AFI_IP].tovpn_sid_locator);
		bgp_vrf->vpn_policy[AFI_IP].tovpn_sid_locator = NULL;

		/* refresh vpnv6 tovpn_sid_locator */
		srv6_locator_free(
			bgp_vrf->vpn_policy[AFI_IP6].tovpn_sid_locator);
		bgp_vrf->vpn_policy[AFI_IP6].tovpn_sid_locator = NULL;

		/* refresh per-vrf tovpn_sid_locator */
		srv6_locator_free(bgp_vrf->tovpn_sid_locator);
		bgp_vrf->tovpn_sid_locator = NULL;
	}
}

/* unset srv6 locator */
int bgp_srv6_locator_unset(struct bgp *bgp)
{
	/* clear function, sids */
	bgp_srv6_sids_unset(bgp);

	/* clear locator name */
	memset(bgp->srv6_locator_name, 0, sizeof(bgp->srv6_locator_name));

	/* clear SRv6 locator */
	if (bgp->srv6_locator) {
		srv6_locator_free(bgp->srv6_locator);
		bgp->srv6_locator = NULL;
	}
	vpn_leak_postchange_all();
	return 0;
}

/* Utility function to get address family from current node.  */
afi_t bgp_node_afi(struct vty *vty)
{
	afi_t afi;
	switch (vty->node) {
	case BGP_IPV6_NODE:
	case BGP_IPV6M_NODE:
	case BGP_IPV6L_NODE:
	case BGP_VPNV6_NODE:
	case BGP_FLOWSPECV6_NODE:
	case BGP_IPV6U_NODE:
		afi = AFI_IP6;
		break;
	case BGP_EVPN_NODE:
		afi = AFI_L2VPN;
		break;
	case BGP_LS_NODE:
		afi = AFI_BGP_LS;
		break;
	default:
		afi = AFI_IP;
		break;
	}
	return afi;
}

/* Utility function to get subsequent address family from current
   node.  */
safi_t bgp_node_safi(struct vty *vty)
{
	safi_t safi;
	switch (vty->node) {
	case BGP_VPNV4_NODE:
	case BGP_VPNV6_NODE:
		safi = SAFI_MPLS_VPN;
		break;
	case BGP_IPV4M_NODE:
	case BGP_IPV6M_NODE:
		safi = SAFI_MULTICAST;
		break;
	case BGP_EVPN_NODE:
		safi = SAFI_EVPN;
		break;
	case BGP_IPV4L_NODE:
	case BGP_IPV6L_NODE:
		safi = SAFI_LABELED_UNICAST;
		break;
	case BGP_FLOWSPECV4_NODE:
	case BGP_FLOWSPECV6_NODE:
		safi = SAFI_FLOWSPEC;
		break;
	case BGP_LS_NODE:
		safi = SAFI_BGP_LS;
		break;
	case BGP_IPV4U_NODE:
	case BGP_IPV6U_NODE:
		safi = SAFI_UNREACH;
		break;
	default:
		safi = SAFI_UNICAST;
		break;
	}
	return safi;
}

/**
 * Converts an AFI in string form to afi_t
 *
 * @param afi string, one of
 *  - "ipv4"
 *  - "ipv6"
 *  - "l2vpn"
 * @return the corresponding afi_t
 */
afi_t bgp_vty_afi_from_str(const char *afi_str)
{
	afi_t afi = AFI_MAX; /* unknown */
	if (strmatch(afi_str, "ipv4"))
		afi = AFI_IP;
	else if (strmatch(afi_str, "ipv6"))
		afi = AFI_IP6;
	else if (strmatch(afi_str, "l2vpn"))
		afi = AFI_L2VPN;
	return afi;
}

int argv_find_and_parse_afi(struct cmd_token **argv, int argc, int *index,
			    afi_t *afi)
{
	int ret = 0;
	if (argv_find(argv, argc, "ipv4", index)) {
		ret = 1;
		if (afi)
			*afi = AFI_IP;
	} else if (argv_find(argv, argc, "ipv6", index)) {
		ret = 1;
		if (afi)
			*afi = AFI_IP6;
	} else if (argv_find(argv, argc, "l2vpn", index)) {
		ret = 1;
		if (afi)
			*afi = AFI_L2VPN;
	}
	return ret;
}

/* supports <unicast|multicast|vpn|labeled-unicast> */
safi_t bgp_vty_safi_from_str(const char *safi_str)
{
	safi_t safi = SAFI_MAX; /* unknown */
	if (strmatch(safi_str, "multicast"))
		safi = SAFI_MULTICAST;
	else if (strmatch(safi_str, "unicast"))
		safi = SAFI_UNICAST;
	else if (strmatch(safi_str, "vpn"))
		safi = SAFI_MPLS_VPN;
	else if (strmatch(safi_str, "evpn"))
		safi = SAFI_EVPN;
	else if (strmatch(safi_str, "labeled-unicast"))
		safi = SAFI_LABELED_UNICAST;
	else if (strmatch(safi_str, "flowspec"))
		safi = SAFI_FLOWSPEC;
	else if (strmatch(safi_str, "unreachability"))
		safi = SAFI_UNREACH;
	return safi;
}

int argv_find_and_parse_safi(struct cmd_token **argv, int argc, int *index,
			     safi_t *safi)
{
	int ret = 0;
	if (argv_find(argv, argc, "unicast", index)) {
		ret = 1;
		if (safi)
			*safi = SAFI_UNICAST;
	} else if (argv_find(argv, argc, "multicast", index)) {
		ret = 1;
		if (safi)
			*safi = SAFI_MULTICAST;
	} else if (argv_find(argv, argc, "labeled-unicast", index)) {
		ret = 1;
		if (safi)
			*safi = SAFI_LABELED_UNICAST;
	} else if (argv_find(argv, argc, "vpn", index)) {
		ret = 1;
		if (safi)
			*safi = SAFI_MPLS_VPN;
	} else if (argv_find(argv, argc, "evpn", index)) {
		ret = 1;
		if (safi)
			*safi = SAFI_EVPN;
	} else if (argv_find(argv, argc, "flowspec", index)) {
		ret = 1;
		if (safi)
			*safi = SAFI_FLOWSPEC;
	} else if (argv_find(argv, argc, "unreachability", index)) {
		ret = 1;
		if (safi)
			*safi = SAFI_UNREACH;
	}
	return ret;
}

int bgp_get_vty(struct bgp **bgp, as_t *as, const char *name,
		enum bgp_instance_type inst_type, const char *as_pretty,
		enum asnotation_mode asnotation)
{
	int ret = bgp_get(bgp, as, name, inst_type, as_pretty, asnotation);

	if (ret == BGP_CREATED) {
		bgp_timers_set(NULL, *bgp, DFLT_BGP_KEEPALIVE, DFLT_BGP_HOLDTIME,
			       DFLT_BGP_CONNECT_RETRY, BGP_DEFAULT_DELAYOPEN);

		if (DFLT_BGP_IMPORT_CHECK)
			SET_FLAG((*bgp)->flags, BGP_FLAG_IMPORT_CHECK);
		if (DFLT_BGP_SHOW_HOSTNAME)
			SET_FLAG((*bgp)->flags, BGP_FLAG_SHOW_HOSTNAME);
		if (DFLT_BGP_SHOW_NEXTHOP_HOSTNAME)
			SET_FLAG((*bgp)->flags, BGP_FLAG_SHOW_NEXTHOP_HOSTNAME);
		if (DFLT_BGP_LOG_NEIGHBOR_CHANGES)
			SET_FLAG((*bgp)->flags, BGP_FLAG_LOG_NEIGHBOR_CHANGES);
		if (DFLT_BGP_DETERMINISTIC_MED)
			SET_FLAG((*bgp)->flags, BGP_FLAG_DETERMINISTIC_MED);
		if (DFLT_BGP_EBGP_REQUIRES_POLICY)
			SET_FLAG((*bgp)->flags, BGP_FLAG_EBGP_REQUIRES_POLICY);
		if (DFLT_BGP_SUPPRESS_DUPLICATES)
			SET_FLAG((*bgp)->flags, BGP_FLAG_SUPPRESS_DUPLICATES);
		if (DFLT_BGP_GRACEFUL_NOTIFICATION)
			SET_FLAG((*bgp)->flags, BGP_FLAG_GRACEFUL_NOTIFICATION);
		if (DFLT_BGP_HARD_ADMIN_RESET)
			SET_FLAG((*bgp)->flags, BGP_FLAG_HARD_ADMIN_RESET);
		if (DFLT_BGP_SOFT_VERSION_CAPABILITY_OLD)
			SET_FLAG((*bgp)->flags, BGP_FLAG_SOFT_VERSION_CAPABILITY_OLD);
		if (DFLT_BGP_SOFT_VERSION_CAPABILITY_NEW)
			SET_FLAG((*bgp)->flags, BGP_FLAG_SOFT_VERSION_CAPABILITY_NEW);
		if (DFLT_BGP_LINK_LOCAL_CAPABILITY)
			SET_FLAG((*bgp)->flags, BGP_FLAG_LINK_LOCAL_CAPABILITY);
		if (DFLT_BGP_DYNAMIC_CAPABILITY)
			SET_FLAG((*bgp)->flags,
				 BGP_FLAG_DYNAMIC_CAPABILITY);
		if (DFLT_BGP_ENFORCE_FIRST_AS)
			SET_FLAG((*bgp)->flags, BGP_FLAG_ENFORCE_FIRST_AS);
		if (DFLT_BGP_RR_ALLOW_OUTBOUND_POLICY)
			SET_FLAG((*bgp)->flags, BGP_FLAG_RR_ALLOW_OUTBOUND_POLICY);
		if (DFLT_BGP_COMPARE_AIGP)
			SET_FLAG((*bgp)->flags, BGP_FLAG_COMPARE_AIGP);
		if (DFLT_BGP_DEFAULT_ORIGINATE_SETONLY_UNCONDITIONAL)
			SET_FLAG((*bgp)->flags, BGP_FLAG_DEFAULT_ORIGINATE_SETONLY_UNCONDITIONAL);

		ret = BGP_SUCCESS;
	}
	return ret;
}

/*
 * Initialize nexthop prefer-global setting for all applicable IPv6 SAFIs.
 * This applies to UNICAST, MULTICAST, and LABELED_UNICAST only.
 */
void bgp_init_ipv6_nexthop_prefer_global(struct bgp *bgp)
{
	safi_t safi;

	if (!DFLT_BGP_IPV6_NEXTHOP_PREFER_GLOBAL)
		return;

	for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++) {
		if (BGP_IPV6_SAFI_SUPPORTS_NEXTHOP_PREFER_GLOBAL(safi))
			bgp->nexthop_prefer_global[AFI_IP6][safi] = true;
	}
}

/*
 * bgp_vty_find_and_parse_afi_safi_bgp
 *
 * For a given 'show ...' command, correctly parse the afi/safi/bgp out from it
 * This function *assumes* that the calling function pre-sets the afi/safi/bgp
 * to appropriate values for the calling function.  This is to allow the
 * calling function to make decisions appropriate for the show command
 * that is being parsed.
 *
 * The show commands are generally of the form:
 * "show [ip] bgp [<view|vrf> VIEWVRFNAME] [<ipv4|ipv6>
 * [<unicast|multicast|vpn|labeled-unicast>]] ..."
 *
 * Since we use argv_find if the show command in particular doesn't have:
 * [ip]
 * [<view|vrf> VIEWVRFNAME]
 * [<ipv4|ipv6> [<unicast|multicast|vpn|labeled-unicast>]]
 * The command parsing should still be ok.
 *
 * vty  -> The vty for the command so we can output some useful data in
 *         the event of a parse error in the vrf.
 * argv -> The command tokens
 * argc -> How many command tokens we have
 * idx  -> The current place in the command, generally should be 0 for this
 * function
 * afi  -> The parsed afi if it was included in the show command, returned here
 * safi -> The parsed safi if it was included in the show command, returned here
 * bgp  -> Pointer to the bgp data structure we need to fill in.
 * use_json -> json is configured or not
 *
 * The function returns the correct location in the parse tree for the
 * last token found.
 *
 * Returns 0 for failure to parse correctly, else the idx position of where
 * it found the last token.
 */
int bgp_vty_find_and_parse_afi_safi_bgp(struct vty *vty,
					struct cmd_token **argv, int argc,
					int *idx, afi_t *afi, safi_t *safi,
					struct bgp **bgp, bool use_json)
{
	char *vrf_name = NULL;

	assert(afi);
	assert(safi);
	assert(bgp);

	if (argv_find(argv, argc, "ip", idx))
		*afi = AFI_IP;

	if (argv_find(argv, argc, "view", idx))
		vrf_name = argv[*idx + 1]->arg;
	else if (argv_find(argv, argc, "vrf", idx)) {
		vrf_name = argv[*idx + 1]->arg;
		if (strmatch(vrf_name, VRF_DEFAULT_NAME))
			vrf_name = NULL;
	}
	if (vrf_name) {
		if (strmatch(vrf_name, "all"))
			*bgp = NULL;
		else {
			*bgp = bgp_lookup_by_name_filter(vrf_name, false);
			if (!*bgp) {
				if (use_json) {
					json_object *json = NULL;
					json = json_object_new_object();
					json_object_string_add(
					  json, "warning",
					  "View/Vrf is unknown");
					vty_json(vty, json);
				}
				else
					vty_out(vty, "View/Vrf %s is unknown\n",
						vrf_name);
				*idx = 0;
				return 0;
			}
		}
	} else {
		*bgp = bgp_get_default();
		if (!*bgp) {
			if (use_json) {
				json_object *json = NULL;
				json = json_object_new_object();
				json_object_string_add(
					json, "warning",
					"Default BGP instance not found");
				vty_json(vty, json);
			}
			else
				vty_out(vty,
					"Default BGP instance not found\n");
			*idx = 0;
			return 0;
		}
	}

	if (argv_find_and_parse_afi(argv, argc, idx, afi))
		argv_find_and_parse_safi(argv, argc, idx, safi);

	*idx += 1;
	return *idx;
}

bool peer_address_self_check(struct bgp *bgp, union sockunion *su)
{
	struct interface *ifp = NULL;
	struct listnode *node;
	struct bgp_listener *listener;
	union sockunion all_su;

	if (su->sa.sa_family == AF_INET) {
		(void)str2sockunion("0.0.0.0", &all_su);
		ifp = if_lookup_by_ipv4_exact(&su->sin.sin_addr, bgp->vrf_id);
	} else if (su->sa.sa_family == AF_INET6) {
		(void)str2sockunion("::", &all_su);
		ifp = if_lookup_by_ipv6_exact(&su->sin6.sin6_addr,
					      su->sin6.sin6_scope_id,
					      bgp->vrf_id);
	}

	if (ifp) {
		for (ALL_LIST_ELEMENTS_RO(bm->listen_sockets, node, listener)) {
			if (sockunion_family(su) !=
			    sockunion_family(&listener->su))
				continue;

			/* If 0.0.0.0/:: is a listener, then treat as self and
			 * reject.
			 */
			if (!sockunion_cmp(&listener->su, su) ||
			    !sockunion_cmp(&listener->su, &all_su))
				return true;
		}
	}

	return false;
}

/* Utility function for looking up peer or peer group.  */
/* This is used only for configuration, so disallow if attempted on
 * a dynamic neighbor.
 */
struct peer *peer_and_group_lookup_vty(struct vty *vty, const char *peer_str)
{
	struct bgp *bgp = VTY_GET_CONTEXT(bgp);
	int ret;
	union sockunion su;
	struct peer *peer = NULL;
	struct peer_group *group = NULL;

	if (!bgp) {
		return NULL;
	}

	ret = str2sockunion(peer_str, &su);
	if (ret == 0) {
		/* IP address, locate peer. */
		peer = peer_lookup(bgp, &su);
	} else {
		/* Not IP, could match either peer configured on interface or a
		 * group. */
		peer = peer_lookup_by_conf_if(bgp, peer_str);
		if (!peer)
			group = peer_group_lookup(bgp, peer_str);
	}

	if (peer) {
		if (peer_dynamic_neighbor(peer)) {
			zlog_warn(
				"%pBP: Operation not allowed on a dynamic neighbor",
				peer);
			vty_out(vty,
				"%% Operation not allowed on a dynamic neighbor\n");
			return NULL;
		}

		return peer;
	}

	if (group)
		return group->conf;

	zlog_warn("Specify remote-as or peer-group commands first before: %s",
		  vty->buf);
	vty_out(vty, "%% Specify remote-as or peer-group commands first\n");

	return NULL;
}

int bgp_vty_return(struct vty *vty, enum bgp_create_error_code ret)
{
	const char *str = NULL;

	switch (ret) {
	case BGP_SUCCESS:
	case BGP_CREATED:
	case BGP_INSTANCE_EXISTS:
	case BGP_GR_NO_OPERATION:
		break;
	case BGP_ERR_INVALID_VALUE:
		str = "Invalid value";
		break;
	case BGP_ERR_INVALID_FLAG:
		str = "Invalid flag";
		break;
	case BGP_ERR_PEER_GROUP_SHUTDOWN:
		str = "Peer-group has been shutdown. Activate the peer-group first";
		break;
	case BGP_ERR_PEER_FLAG_CONFLICT:
		str = "Can't set override-capability and strict-capability-match at the same time";
		break;
	case BGP_ERR_PEER_GROUP_NO_REMOTE_AS:
		str = "Specify remote-as or peer-group remote AS first";
		break;
	case BGP_ERR_PEER_GROUP_CANT_CHANGE:
		str = "Cannot change the peer-group. Deconfigure first";
		break;
	case BGP_ERR_PEER_GROUP_MISMATCH:
		str = "Peer is not a member of this peer-group";
		break;
	case BGP_ERR_PEER_FILTER_CONFLICT:
		str = "Prefix/distribute list can not co-exist";
		break;
	case BGP_ERR_NOT_INTERNAL_PEER:
		str = "Invalid command. Not an internal neighbor";
		break;
	case BGP_ERR_REMOVE_PRIVATE_AS:
		str = "remove-private-AS cannot be configured for IBGP peers";
		break;
	case BGP_ERR_CANNOT_HAVE_LOCAL_AS_SAME_AS:
		str = "Cannot have local-as same as BGP AS number";
		break;
	case BGP_ERR_TCPSIG_FAILED:
		str = "Error while applying TCP-Sig to session(s)";
		break;
	case BGP_ERR_NO_EBGP_MULTIHOP_WITH_TTLHACK:
		str = "ebgp-multihop and ttl-security cannot be configured together";
		break;
	case BGP_ERR_NO_IBGP_WITH_TTLHACK:
		str = "ttl-security only allowed for EBGP peers";
		break;
	case BGP_ERR_AS_OVERRIDE:
		str = "as-override cannot be configured for IBGP peers";
		break;
	case BGP_ERR_INVALID_DYNAMIC_NEIGHBORS_LIMIT:
		str = "Invalid limit for number of dynamic neighbors";
		break;
	case BGP_ERR_DYNAMIC_NEIGHBORS_RANGE_EXISTS:
		str = "Dynamic neighbor listen range already exists";
		break;
	case BGP_ERR_INVALID_FOR_DYNAMIC_PEER:
		str = "Operation not allowed on a dynamic neighbor";
		break;
	case BGP_ERR_INVALID_FOR_DIRECT_PEER:
		str = "Operation not allowed on a directly connected neighbor";
		break;
	case BGP_ERR_PEER_SAFI_CONFLICT:
		str = "Cannot activate peer for both 'ipv4 unicast' and 'ipv4 labeled-unicast'";
		break;
	case BGP_ERR_GR_INVALID_CMD:
		str = "The Graceful Restart command used is not valid at this moment.";
		break;
	case BGP_ERR_GR_OPERATION_FAILED:
		str = "The Graceful Restart Operation failed due to an err.";
		break;
	case BGP_ERR_DYNAMIC_NEIGHBORS_RANGE_NOT_FOUND:
		str = "Range specified cannot be deleted because it is not part of current config.";
		break;
	case BGP_ERR_INSTANCE_MISMATCH:
		str = "Instance specified does not match the current instance.";
		break;
	case BGP_ERR_NO_INTERFACE_CONFIG:
		str = "Interface specified is not being used for interface based peer.";
		break;
	case BGP_ERR_SOFT_RECONFIG_UNCONFIGURED:
		str = "No configuration already specified for soft reconfiguration.";
		break;
	case BGP_ERR_AS_MISMATCH:
		str = "BGP is already running.";
		break;
	case BGP_ERR_AF_UNCONFIGURED:
		str = "AFI/SAFI specified is not currently configured.";
		break;
	case BGP_ERR_INVALID_AS:
		str = "Confederation AS specified is the same AS as our AS.";
		break;
	case BGP_ERR_INVALID_ROLE_NAME:
		str = "Invalid role name";
		break;
	case BGP_ERR_INVALID_INTERNAL_ROLE:
		str = "External roles can be set only on eBGP session";
		break;
	}
	if (str) {
		vty_out(vty, "%% %s\n", str);
		return CMD_WARNING_CONFIG_FAILED;
	}
	return CMD_SUCCESS;
}

/* BGP clear sort. */
enum clear_sort {
	clear_all,
	clear_peer,
	clear_group,
	clear_external,
	clear_as
};

static void bgp_clear_vty_error(struct vty *vty, struct peer *peer, afi_t afi,
				safi_t safi, int error)
{
	switch (error) {
	case BGP_ERR_AF_UNCONFIGURED:
		if (vty)
			vty_out(vty,
				"%% BGP: Enable %s address family for the neighbor %s\n",
				get_afi_safi_str(afi, safi, false), peer->host);
		else
			zlog_warn(
				"%% BGP: Enable %s address family for the neighbor %s",
				get_afi_safi_str(afi, safi, false), peer->host);
		break;
	case BGP_ERR_SOFT_RECONFIG_UNCONFIGURED:
		if (vty)
			vty_out(vty,
				"%% BGP: Inbound soft reconfig for %s not possible as it\n      has neither refresh capability, nor inbound soft reconfig\n",
				peer->host);
		else
			zlog_warn(
				"%% BGP: Inbound soft reconfig for %s not possible as it has neither refresh capability, nor inbound soft reconfig",
				peer->host);
		break;
	default:
		break;
	}
}

static int bgp_peer_clear(struct peer *peer, afi_t afi, safi_t safi,
			  struct listnode **nnode, enum bgp_clear_type stype)
{
	int ret = 0;
	struct peer_af *paf;

	/* if afi/.safi not specified, spin thru all of them */
	if ((afi == AFI_UNSPEC) && (safi == SAFI_UNSPEC)) {
		afi_t tmp_afi;
		safi_t tmp_safi;
		enum bgp_af_index index;

		for (index = BGP_AF_START; index < BGP_AF_MAX; index++) {
			paf = peer->peer_af_array[index];
			if (!paf)
				continue;

			tmp_afi = paf->afi;
			tmp_safi = paf->safi;
			if (!peer->afc[tmp_afi][tmp_safi])
				continue;

			if (stype == BGP_CLEAR_HARD)
				ret = peer_clear(peer, nnode);
			else
				ret = peer_clear_soft(peer, tmp_afi, tmp_safi,
						      stype);
		}
	/* if afi specified and safi not, spin thru safis on this afi */
	} else if (safi == SAFI_UNSPEC) {
		safi_t tmp_safi;

		for (tmp_safi = SAFI_UNICAST;
		     tmp_safi < SAFI_MAX; tmp_safi++) {
			if (!peer->afc[afi][tmp_safi])
				continue;

			if (stype == BGP_CLEAR_HARD)
				ret = peer_clear(peer, nnode);
			else
				ret = peer_clear_soft(peer, afi,
						      tmp_safi, stype);
		}
	/* both afi/safi specified, let the caller know if not defined */
	} else {
		if (!peer->afc[afi][safi])
			return 1;

		if (stype == BGP_CLEAR_HARD)
			ret = peer_clear(peer, nnode);
		else
			ret = peer_clear_soft(peer, afi, safi, stype);
	}

	return ret;
}

/* `clear ip bgp' functions. */
static int bgp_clear(struct vty *vty, struct bgp *bgp, afi_t afi, safi_t safi,
		     enum clear_sort sort, enum bgp_clear_type stype,
		     const char *arg)
{
	int ret = 0;
	bool found = false;
	struct peer *peer;
	bool afi_safi_unspec = false;
	bool use_batch = false;

	VTY_BGP_GR_DEFINE_LOOP_VARIABLE;

	afi_safi_unspec = ((afi == AFI_UNSPEC) && (safi == SAFI_UNSPEC));

	/*
	 * A hard clear resets the whole session whatever address family is
	 * given, the family only selects the peers, so it can be batched too.
	 */
	use_batch = afi_safi_unspec || (stype == BGP_CLEAR_HARD);

	/* Clear all neighbors. */
	/*
	 * Pass along pointer to next node to peer_clear() when walking all
	 * nodes on the BGP instance as that may get freed if it is a
	 * doppelganger
	 */
	if (sort == clear_all) {
		if (use_batch)
			bgp_clearing_batch_begin(bgp);
		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {

			bgp_peer_gr_flags_update(peer);

			if (CHECK_FLAG(peer->flags, PEER_FLAG_GRACEFUL_RESTART))
				gr_router_detected = true;

			ret = bgp_peer_clear(peer, afi, safi, &nnode,
							  stype);

			if (ret < 0)
				bgp_clear_vty_error(vty, peer, afi, safi, ret);
		}

		if (gr_router_detected
		    && bgp->present_zebra_gr_state == ZEBRA_GR_DISABLE) {
			bgp_zebra_send_capabilities(bgp, false);
		} else if (!gr_router_detected
			   && bgp->present_zebra_gr_state == ZEBRA_GR_ENABLE) {
			bgp_zebra_send_capabilities(bgp, true);
		}

		/* This is to apply read-only mode on this clear. */
		if (stype == BGP_CLEAR_HARD) {
			bgp->update_delay_over = 0;
			event_cancel(&bgp->t_advertisement_delay);
			bgp->advertisement_delay_started = 0;
			bgp->advertisement_delay_over = 0;
		}

		if (use_batch)
			bgp_clearing_batch_end_event_start(bgp);
		return CMD_SUCCESS;
	}

	/* Clear specified neighbor. */
	if (sort == clear_peer) {
		union sockunion su;

		/* Make sockunion for lookup. */
		ret = str2sockunion(arg, &su);
		if (ret < 0) {
			peer = peer_lookup_by_conf_if(bgp, arg);
			if (!peer) {
				peer = peer_lookup_by_hostname(bgp, arg);
				if (!peer) {
					vty_out(vty,
						"Malformed address or name: %s\n",
						arg);
					return CMD_WARNING;
				}
			}
		} else {
			peer = peer_lookup(bgp, &su);
			if (!peer) {
				vty_out(vty,
					"%% BGP: Unknown neighbor - \"%s\"\n",
					arg);
				return CMD_WARNING;
			}
		}

		bgp_peer_gr_flags_update(peer);
		VTY_BGP_GR_ROUTER_DETECT(bgp, peer, peer->bgp->peer);
		VTY_SEND_BGP_GR_CAPABILITY_TO_ZEBRA(peer->bgp, ret);

		ret = bgp_peer_clear(peer, afi, safi, NULL, stype);

		/* if afi/safi not defined for this peer, let caller know */
		if (ret == 1)
			ret = BGP_ERR_AF_UNCONFIGURED;

		if (ret < 0)
			bgp_clear_vty_error(vty, peer, afi, safi, ret);

		return CMD_SUCCESS;
	}

	/* Clear all neighbors belonging to a specific peer-group. */
	if (sort == clear_group) {
		struct peer_group *group;

		group = peer_group_lookup(bgp, arg);
		if (!group) {
			vty_out(vty, "%% BGP: No such peer-group %s\n", arg);
			return CMD_WARNING;
		}

		if (use_batch)
			bgp_clearing_batch_begin(bgp);
		for (ALL_LIST_ELEMENTS(group->peer, node, nnode, peer)) {
			ret = bgp_peer_clear(peer, afi, safi, &nnode, stype);

			if (ret < 0)
				bgp_clear_vty_error(vty, peer, afi, safi, ret);
			else
				found = true;
		}
		if (use_batch)
			bgp_clearing_batch_end_event_start(bgp);

		if (!found)
			vty_out(vty,
				"%% BGP: No %s peer belonging to peer-group %s is configured\n",
				get_afi_safi_str(afi, safi, false), arg);

		return CMD_SUCCESS;
	}

	/* Clear all external (eBGP) neighbors. */
	if (sort == clear_external) {
		if (use_batch)
			bgp_clearing_batch_begin(bgp);
		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
			if (peer->sort == BGP_PEER_IBGP)
				continue;

			bgp_peer_gr_flags_update(peer);

			if (CHECK_FLAG(peer->flags, PEER_FLAG_GRACEFUL_RESTART))
				gr_router_detected = true;

			ret = bgp_peer_clear(peer, afi, safi, &nnode, stype);

			if (ret < 0)
				bgp_clear_vty_error(vty, peer, afi, safi, ret);
			else
				found = true;
		}

		if (gr_router_detected
		    && bgp->present_zebra_gr_state == ZEBRA_GR_DISABLE) {
			bgp_zebra_send_capabilities(bgp, false);
		} else if (!gr_router_detected
			   && bgp->present_zebra_gr_state == ZEBRA_GR_ENABLE) {
			bgp_zebra_send_capabilities(bgp, true);
		}
		if (use_batch)
			bgp_clearing_batch_end_event_start(bgp);
		if (!found)
			vty_out(vty,
				"%% BGP: No external %s peer is configured\n",
				get_afi_safi_str(afi, safi, false));

		return CMD_SUCCESS;
	}

	/* Clear all neighbors belonging to a specific AS. */
	if (sort == clear_as) {
		as_t as = 0;

		if (!asn_str2asn(arg, &as)) {
			vty_out(vty, "%% BGP: No such AS %s\n", arg);
			return CMD_WARNING;
		}

		if (use_batch)
			bgp_clearing_batch_begin(bgp);
		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
			if (peer->as != as)
				continue;

			bgp_peer_gr_flags_update(peer);

			if (CHECK_FLAG(peer->flags, PEER_FLAG_GRACEFUL_RESTART))
				gr_router_detected = true;

			ret = bgp_peer_clear(peer, afi, safi, &nnode, stype);

			if (ret < 0)
				bgp_clear_vty_error(vty, peer, afi, safi, ret);
			else
				found = true;
		}

		if (gr_router_detected
		    && bgp->present_zebra_gr_state == ZEBRA_GR_DISABLE) {
			bgp_zebra_send_capabilities(bgp, false);
		} else if (!gr_router_detected
			   && bgp->present_zebra_gr_state == ZEBRA_GR_ENABLE) {
			bgp_zebra_send_capabilities(bgp, true);
		}

		if (use_batch)
			bgp_clearing_batch_end_event_start(bgp);
		if (!found)
			vty_out(vty,
				"%% BGP: No %s peer is configured with AS %s\n",
				get_afi_safi_str(afi, safi, false), arg);

		return CMD_SUCCESS;
	}

	return CMD_SUCCESS;
}

static int bgp_clear_vty(struct vty *vty, const char *name, afi_t afi,
			 safi_t safi, enum clear_sort sort,
			 enum bgp_clear_type stype, const char *arg)
{
	struct bgp *bgp;

	/* BGP structure lookup. */
	if (name) {
		bgp = bgp_lookup_by_name(name);
		if (bgp == NULL) {
			vty_out(vty, "Can't find BGP instance %s\n", name);
			return CMD_WARNING;
		}
	} else {
		bgp = bgp_get_default();
		if (bgp == NULL) {
			vty_out(vty, "No BGP process is configured\n");
			return CMD_WARNING;
		}
	}

	return bgp_clear(vty, bgp, afi, safi, sort, stype, arg);
}


void bgp_clear_soft_in(struct bgp *bgp, afi_t afi, safi_t safi)
{
	bgp_clear(NULL, bgp, afi, safi, clear_all, BGP_CLEAR_SOFT_IN, NULL);
}

void bgp_clear_soft_out(struct bgp *bgp, afi_t afi, safi_t safi)
{
	bgp_clear(NULL, bgp, afi, safi, clear_all, BGP_CLEAR_SOFT_OUT, NULL);
}

void bgp_clear_all_soft_in(struct bgp *bgp)
{
	afi_t afi;
	safi_t safi;

	FOREACH_AFI_SAFI (afi, safi)
		bgp_clear_soft_in(bgp, afi, safi);
}

void bgp_clear_all_soft_out(struct bgp *bgp)
{
	afi_t afi;
	safi_t safi;

	FOREACH_AFI_SAFI (afi, safi)
		bgp_clear_soft_out(bgp, afi, safi);
}

static void bgp_need_listening(struct bgp *bgp, struct vty *vty)
{
	struct listnode *node;
	struct bgp_listener *listener = NULL;

	for (ALL_LIST_ELEMENTS_RO(bm->listen_sockets, node, listener)) {
		if (listener->bgp == bgp)
			break;
	}
	if (listener == NULL) {
		struct vrf *vrf;

		SET_FLAG(bgp->flags, BGP_FLAG_VRF_MAY_LISTEN);
		vrf = bgp_vrf_lookup_by_instance_type(bgp);
		bgp_handle_socket(bgp, vrf, VRF_UNKNOWN, true);
	}
}

void bgp_nb_need_listening(struct bgp *bgp)
{
	bgp_need_listening(bgp, NULL);
}

#include "bgpd/bgp_vty_clippy.c"

DEFUN_HIDDEN (bgp_local_mac,
              bgp_local_mac_cmd,
              "bgp local-mac vni " CMD_VNI_RANGE " mac WORD seq (0-4294967295)",
              BGP_STR
              "Local MAC config\n"
              "VxLAN Network Identifier\n"
              "VNI number\n"
              "local mac\n"
              "mac address\n"
              "mac-mobility sequence\n"
              "seq number\n")
{
	int rv;
	vni_t vni;
	struct ethaddr mac;
	struct ipaddr ip;
	uint32_t seq;
	struct bgp *bgp;

	vni = strtoul(argv[3]->arg, NULL, 10);
	if (!prefix_str2mac(argv[5]->arg, &mac)) {
		vty_out(vty, "%% Malformed MAC address\n");
		return CMD_WARNING;
	}
	memset(&ip, 0, sizeof(ip));
	seq = strtoul(argv[7]->arg, NULL, 10);

	bgp = bgp_get_default();
	if (!bgp || IS_BGP_INSTANCE_HIDDEN(bgp)) {
		vty_out(vty, "Default BGP instance is not there\n");
		return CMD_WARNING;
	}

	rv = bgp_evpn_local_macip_add(bgp, vni, &mac, &ip, 0 /* flags */, seq,
			zero_esi);
	if (rv < 0) {
		vty_out(vty, "Internal error\n");
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN_HIDDEN (no_bgp_local_mac,
              no_bgp_local_mac_cmd,
              "no bgp local-mac vni " CMD_VNI_RANGE " mac WORD",
              NO_STR
              BGP_STR
              "Local MAC config\n"
              "VxLAN Network Identifier\n"
              "VNI number\n"
              "local mac\n"
              "mac address\n")
{
	int rv;
	vni_t vni;
	struct ethaddr mac;
	struct ipaddr ip;
	struct bgp *bgp;

	vni = strtoul(argv[4]->arg, NULL, 10);
	if (!prefix_str2mac(argv[6]->arg, &mac)) {
		vty_out(vty, "%% Malformed MAC address\n");
		return CMD_WARNING;
	}
	memset(&ip, 0, sizeof(ip));

	bgp = bgp_get_default();
	if (!bgp || IS_BGP_INSTANCE_HIDDEN(bgp)) {
		vty_out(vty, "Default BGP instance is not there\n");
		return CMD_WARNING;
	}

	rv = bgp_evpn_local_macip_del(bgp, vni, &mac, &ip, ZEBRA_NEIGH_ACTIVE);
	if (rv < 0) {
		vty_out(vty, "Internal error\n");
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

/* bgp session-dscp */

/* BGP router-id.  */

DEFPY (bgp_router_id,
       bgp_router_id_cmd,
       "bgp router-id A.B.C.D",
       BGP_STR
       "Override configured router identifier\n"
       "Manually configured router identifier\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	bgp_router_id_static_set(bgp, router_id);
	return CMD_SUCCESS;
}

DEFPY(bgp_community_alias, bgp_community_alias_cmd,
      "[no$no] bgp community alias WORD$community ALIAS_NAME$alias_name",
      NO_STR BGP_STR
      "Add community specific parameters\n"
      "Create an alias for a community\n"
      "Community (AA:BB or AA:BB:CC)\n"
      "Alias name\n")
{
	struct community_alias ca = {};
	struct community_alias *lookup_community;
	struct community_alias *lookup_alias;
	struct community *comm;
	struct lcommunity *lcomm;
	uint8_t invalid = 0;

	comm = community_str2com(community);
	if (!comm)
		invalid++;
	community_free(&comm);

	lcomm = lcommunity_str2com(community);
	if (!lcomm)
		invalid++;
	lcommunity_free(&lcomm);

	if (invalid > 1) {
		vty_out(vty, "Invalid community format\n");
		return CMD_WARNING;
	}

	strlcpy(ca.community, community, sizeof(ca.community));
	strlcpy(ca.alias, alias_name, sizeof(ca.alias));

	lookup_community = bgp_ca_community_lookup(&ca);
	lookup_alias = bgp_ca_alias_lookup(&ca);

	if (no) {
		bgp_ca_alias_delete(&ca);
		bgp_ca_community_delete(&ca);
	} else {
		if (lookup_alias) {
			/* Lookup if community hash table has an item
			 * with the same alias name.
			 */
			strlcpy(ca.community, lookup_alias->community,
				sizeof(ca.community));
			if (bgp_ca_community_lookup(&ca)) {
				vty_out(vty,
					"community (%s) already has this alias (%s)\n",
					lookup_alias->community,
					lookup_alias->alias);
				return CMD_WARNING;
			}
			bgp_ca_alias_delete(&ca);
		}

		if (lookup_community) {
			/* Lookup if alias hash table has an item
			 * with the same community.
			 */
			strlcpy(ca.alias, lookup_community->alias,
				sizeof(ca.alias));
			if (bgp_ca_alias_lookup(&ca)) {
				vty_out(vty,
					"alias (%s) already has this community (%s)\n",
					lookup_community->alias,
					lookup_community->community);
				return CMD_WARNING;
			}
			bgp_ca_community_delete(&ca);
		}

		bgp_ca_alias_insert(&ca);
		bgp_ca_community_insert(&ca);
	}

	return CMD_SUCCESS;
}

/* Update-delay configuration */

/* BGP timers.  */

/* BGP minimum holdtime.  */


#if CONFDATE > 20271101
CPP_NOTICE("Flip default and deprecate `bgp default-originate set-only-unconditional` knob")
#endif
int bgp_inst_gr_config(struct bgp *bgp, bool on, bool disable)
{
	int ret = BGP_GR_FAILURE;

	/*
	 * Reset gr_select_defer_evaluated if startup timer is running
	 * so that deferred path selection can be reevaluated once
	 * sessions come back up after BGP session reset
	 */
	if (event_is_scheduled(bgp->t_startup))
		bgp->gr_select_defer_evaluated = false;

	/*
	 * Update the instance and all its peers, if appropriate.
	 * Then, inform zebra of BGP's GR capabilities, if needed.
	 */
	if (disable)
		ret = bgp_gr_update_all(bgp, on ? GLOBAL_DISABLE_CMD
						: NO_GLOBAL_DISABLE_CMD);
	else
		ret = bgp_gr_update_all(bgp,
					on ? GLOBAL_GR_CMD : NO_GLOBAL_GR_CMD);

	int zret = BGP_GR_SUCCESS;

	VTY_BGP_GR_ROUTER_DETECT_AND_SEND_CAPABILITY_TO_ZEBRA(bgp, bgp->peer,
							      zret);
	(void)zret;
	return ret;
}

/*
 * Apply daemon-wide (CONFIG_NODE / bm) graceful-restart mode.
 * Returns BGP_GR_SUCCESS or BGP_GR_FAILURE.
 */
int bgp_global_gr_config(bool on, bool disable, char *errmsg, size_t errmsg_len)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;
	int ret = BGP_GR_SUCCESS;

	/* Idempotent already-on / already-off checks */
	if (disable) {
		if ((on && CHECK_FLAG(bm->flags, BM_FLAG_GR_DISABLED)) ||
		    (!on && !CHECK_FLAG(bm->flags, BM_FLAG_GR_DISABLED)))
			return BGP_GR_SUCCESS;
	} else {
		if ((on && CHECK_FLAG(bm->flags, BM_FLAG_GR_RESTARTER)) ||
		    (!on && !CHECK_FLAG(bm->flags, BM_FLAG_GR_RESTARTER)))
			return BGP_GR_SUCCESS;
	}

	/* Per-vrf mutual exclusion is NB_EV_VALIDATE / YANG candidate only. */

	if (on) {
		if (disable) {
			UNSET_FLAG(bm->flags, BM_FLAG_GR_RESTARTER);
			SET_FLAG(bm->flags, BM_FLAG_GR_DISABLED);
		} else {
			SET_FLAG(bm->flags, BM_FLAG_GR_RESTARTER);
			UNSET_FLAG(bm->flags, BM_FLAG_GR_DISABLED);
		}
	} else {
		if (disable)
			UNSET_FLAG(bm->flags, BM_FLAG_GR_DISABLED);
		else
			UNSET_FLAG(bm->flags, BM_FLAG_GR_RESTARTER);
	}

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		int iret = bgp_inst_gr_config(bgp, on, disable);

		if (iret != BGP_GR_SUCCESS && iret != BGP_GR_NO_OPERATION) {
			ret = iret;
			if (errmsg && errmsg_len)
				snprintfrr(errmsg, errmsg_len,
					   "Applying global graceful-restart %s config to %s failed, error %d",
					   disable ? "disable" : "", bgp->name_pretty, iret);
		}
	}

	return ret;
}

int bgp_global_graceful_shutdown_set(bool enable, char *errmsg, size_t errmsg_len)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;

	if (enable) {
		if (CHECK_FLAG(bm->flags, BM_FLAG_GRACEFUL_SHUTDOWN))
			return BGP_GR_SUCCESS;
		/* Per-vrf mutual exclusion is NB_EV_VALIDATE / YANG only. */
		SET_FLAG(bm->flags, BM_FLAG_GRACEFUL_SHUTDOWN);
	} else {
		if (!CHECK_FLAG(bm->flags, BM_FLAG_GRACEFUL_SHUTDOWN))
			return BGP_GR_SUCCESS;
		UNSET_FLAG(bm->flags, BM_FLAG_GRACEFUL_SHUTDOWN);
	}

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp))
		bgp_initiate_graceful_shut_unshut(bgp);

	return BGP_GR_SUCCESS;
}

/*
 * Reset the BGP session since there's a change
 * in GR capability
 */
void bgp_update_graceful_restart_capability(struct peer *peer)
{
	enum peer_mode peer_gr_mode;
	enum global_mode global_gr_mode;

	global_gr_mode = bgp_global_gr_mode_get(peer->bgp);

	peer_gr_mode = bgp_peer_gr_mode_get(peer);

	/*
	 * Skip if peer is not in graceful restart mode
	 */
	if (!((peer_gr_mode == PEER_GR) ||
	      (peer_gr_mode == PEER_GLOBAL_INHERIT && global_gr_mode == GLOBAL_GR)))
		return;

	if (BGP_DEBUG(graceful_restart, GRACEFUL_RESTART))
		zlog_debug("Resetting session for %s: Peer GR mode %s, Global GR mode %s",
			   peer->host, print_peer_gr_mode(peer_gr_mode),
			   print_global_gr_mode(global_gr_mode));

	/*
	 * Reset the session so that the updated capability can be
	 * exchanged again
	 */
	if (BGP_IS_VALID_STATE_FOR_NOTIF(peer->connection->status)) {
		peer_set_last_reset(peer, PEER_DOWN_CAPABILITY_CHANGE);
		bgp_notify_send(peer->connection, BGP_NOTIFY_CEASE, BGP_NOTIFY_CEASE_CONFIG_CHANGE);
	}
}

void bgp_initiate_graceful_shut_unshut(struct bgp *bgp)
{
	bgp_static_redo_import_check(bgp);
	bgp_redistribute_redo(bgp);
	bgp_clear_all_soft_out(bgp);
	bgp_clear_all_soft_in(bgp);
}




/*
 * Check if there is no neighbors nor listening range on bgp
 */
static void bgp_may_stop_listening(struct bgp *bgp, struct vty *vty)
{
	struct listnode *node, *nnode;
	struct peer_group *group;
	struct vrf *vrf;
	afi_t afi;

	if (bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)
		return;

	for (ALL_LIST_ELEMENTS(bgp->group, node, nnode, group)) {
		for (afi = AFI_IP; afi < AFI_MAX; afi++) {
			if (!list_isempty(group->listen_range[afi]))
				return;
		}
	}

	if (!list_isempty(bgp->peer))
		return;

	vrf = bgp_vrf_lookup_by_instance_type(bgp);
	bgp_handle_socket(bgp, vrf, VRF_UNKNOWN, false);
	UNSET_FLAG(bgp->flags, BGP_FLAG_VRF_MAY_LISTEN);
}

void bgp_listen_range_warn(struct vty *vty, const struct peer_group *group,
			   const struct prefix *range)
{
	if (range->prefixlen || group->conf->password)
		return;

	vty_out(vty,
		"%% Listen range %pFX of peer-group %s accepts connections from any address without a password\n",
		range, group->name);
}

void bgp_listen_range_warn_group(struct vty *vty, const struct peer_group *group)
{
	struct listnode *node;
	struct prefix *range;
	afi_t afi;

	for (afi = AFI_IP; afi < AFI_MAX; afi++)
		for (ALL_LIST_ELEMENTS_RO(group->listen_range[afi], node, range))
			bgp_listen_range_warn(vty, group, range);
}

void bgp_nb_may_stop_listening(struct bgp *bgp)
{
	bgp_may_stop_listening(bgp, NULL);
}




/*
 * Send dynamic capability on the peer(s) that own the TCP BGP session.
 * The peer-group template (PEER_STATUS_GROUP) stays Idle; members in
 * peer->group->peer are Established.
 */
static void bgp_vty_capability_send_dynamic_peer_group(struct peer *peer, afi_t afi, safi_t safi,
						       int capability_code, int action)
{
	struct listnode *node;
	struct peer *member;
	struct peer_group *pg;

	if (!peer)
		return;

	if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		pg = peer->group;
		if (!pg)
			return;
		for (ALL_LIST_ELEMENTS_RO(pg->peer, node, member))
			bgp_capability_send(member->connection, afi, safi, capability_code,
					    action);
	} else {
		bgp_capability_send(peer->connection, afi, safi, capability_code, action);
	}
}


/* Re-evaluate routes when the role changes */
void bgp_vty_role_update(struct peer *peer, int action)
{
	struct listnode *node;
	struct peer *member;

	bgp_vty_capability_send_dynamic_peer_group(peer, AFI_IP, SAFI_UNICAST,
						   CAPABILITY_CODE_ROLE, action);

	if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		for (ALL_LIST_ELEMENTS_RO(peer->group->peer, node, member)) {
			peer_clear_soft(member, AFI_IP, SAFI_UNICAST, BGP_CLEAR_SOFT_BOTH);
			peer_clear_soft(member, AFI_IP6, SAFI_UNICAST, BGP_CLEAR_SOFT_BOTH);
		}

		return;
	}

	peer_clear_soft(peer, AFI_IP, SAFI_UNICAST, BGP_CLEAR_SOFT_BOTH);
	peer_clear_soft(peer, AFI_IP6, SAFI_UNICAST, BGP_CLEAR_SOFT_BOTH);
}








DEFPY (show_ip_bgp_neighbor_damp_param,
       show_ip_bgp_neighbor_damp_param_cmd,
       "show [ip] bgp [<ipv4|ipv6> [unicast]] neighbors <A.B.C.D|X:X::X:X|WORD>$neighbor dampening parameters [json]$json",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_AFI_HELP_STR
       "Address Family modifier\n"
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Neighbor route-flap dampening information\n"
       "Display detail of configured dampening parameters\n"
       JSON_STR)
{
	bool use_json = false;
	int idx = 0;
	afi_t afi = AFI_IP;
	safi_t safi = SAFI_UNICAST;
	struct peer *peer;

	if (argv_find(argv, argc, "ip", &idx))
		afi = AFI_IP;
	if (argv_find(argv, argc, "ipv4", &idx))
		afi = AFI_IP;
	if (argv_find(argv, argc, "ipv6", &idx))
		afi = AFI_IP6;
	peer = peer_and_group_lookup_vty(vty, neighbor);
	if (!peer)
		return CMD_WARNING;
	if (json)
		use_json = true;
	bgp_show_peer_dampening_parameters(vty, peer, afi, safi, use_json);
	return CMD_SUCCESS;
}

int set_ecom_list(struct vty *vty, int argc, struct cmd_token **argv, struct ecommunity **list,
		  bool is_rt6)
{
	struct ecommunity *ecom = NULL;
	struct ecommunity *ecomadd;

	for (; argc; --argc, ++argv) {
		if (is_rt6)
			ecomadd = ecommunity_str2com_ipv6(argv[0]->arg,
						ECOMMUNITY_ROUTE_TARGET,
						0);
		else
			ecomadd = ecommunity_str2com(argv[0]->arg,
						ECOMMUNITY_ROUTE_TARGET,
						0);
		if (!ecomadd) {
			vty_out(vty, "Malformed community-list value\n");
			if (ecom)
				ecommunity_free(&ecom);
			return CMD_WARNING_CONFIG_FAILED;
		}

		if (ecom) {
			ecommunity_merge(ecom, ecomadd);
			ecommunity_free(&ecomadd);
		} else {
			ecom = ecomadd;
		}
	}

	if (*list) {
		ecommunity_free(&*list);
	}
	*list = ecom;

	return CMD_SUCCESS;
}

#ifdef KEEP_OLD_VPN_COMMANDS
#endif /* KEEP_OLD_VPN_COMMANDS */

void bgp_segment_routing_srv6_hencaps_refresh(struct bgp *bgp)
{
	struct bgp *bgp_inst;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, bgp_inst)) {
		bgp_zebra_update_srv6_encap_routes(bgp_inst, AFI_IP, bgp, false);
		bgp_zebra_update_srv6_encap_routes(bgp_inst, AFI_IP6, bgp, false);

		bgp_zebra_update_srv6_encap_routes(bgp_inst, AFI_IP, bgp, true);
		bgp_zebra_update_srv6_encap_routes(bgp_inst, AFI_IP6, bgp, true);
	}
}

void bgp_srv6_only_change(struct bgp *bgp, bool enable)
{
	struct bgp *bgp_inst;
	struct listnode *node;

	/* pre-change */
	if (bgp == bgp_get_default()) {
		/* srv6-only changed on default BGP instance, refresh importation to vrf */
		for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, bgp_inst)) {
			if (bgp_inst->inst_type == BGP_INSTANCE_TYPE_VIEW)
				continue;
			vpn_leak_prechange(BGP_VPN_POLICY_DIR_FROMVPN, AFI_IP, bgp_get_default(),
					   bgp_inst);
			vpn_leak_prechange(BGP_VPN_POLICY_DIR_FROMVPN, AFI_IP6, bgp_get_default(),
					   bgp_inst);
		}
	}
	vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, AFI_IP, bgp_get_default(), bgp);
	vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, AFI_IP6, bgp_get_default(), bgp);

	bgp->srv6_only = enable;

	/* post-change */
	if (bgp_get_default() == bgp) {
		/* srv6-only changed on default BGP instance, refresh importation to vrf */
		for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, bgp_inst)) {
			if (bgp_inst->inst_type == BGP_INSTANCE_TYPE_VIEW)
				continue;
			vpn_leak_postchange(BGP_VPN_POLICY_DIR_FROMVPN, AFI_IP, bgp_get_default(),
					    bgp_inst);
			vpn_leak_postchange(BGP_VPN_POLICY_DIR_FROMVPN, AFI_IP6, bgp_get_default(),
					    bgp_inst);
		}
	}
	vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, AFI_IP, bgp_get_default(), bgp);
	vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, AFI_IP6, bgp_get_default(), bgp);
}

DEFPY (show_bgp_srv6,
       show_bgp_srv6_cmd,
       "show bgp segment-routing srv6",
       SHOW_STR
       BGP_STR
       "BGP Segment Routing\n"
       "BGP Segment Routing SRv6\n")
{
	struct bgp *bgp;
	struct listnode *node;
	struct srv6_locator_chunk *chunk;
	struct bgp_srv6_function *func;

	bgp = bgp_get_default();
	if (!bgp)
		return CMD_SUCCESS;

	vty_out(vty, "locator_name: %s\n", bgp->srv6_locator_name);
	if (bgp->srv6_locator) {
		vty_out(vty, "  prefix: %pFX\n", &bgp->srv6_locator->prefix);
		vty_out(vty, "  block-length: %d\n",
			bgp->srv6_locator->block_bits_length);
		vty_out(vty, "  node-length: %d\n",
			bgp->srv6_locator->node_bits_length);
		vty_out(vty, "  func-length: %d\n",
			bgp->srv6_locator->function_bits_length);
		vty_out(vty, "  arg-length: %d\n",
			bgp->srv6_locator->argument_bits_length);
	}
	vty_out(vty, "locator_chunks:\n");
	for (ALL_LIST_ELEMENTS_RO(bgp->srv6_locator_chunks, node, chunk)) {
		vty_out(vty, "- %pFX\n", &chunk->prefix);
		vty_out(vty, "  block-length: %d\n", chunk->block_bits_length);
		vty_out(vty, "  node-length: %d\n", chunk->node_bits_length);
		vty_out(vty, "  func-length: %d\n",
			chunk->function_bits_length);
		vty_out(vty, "  arg-length: %d\n", chunk->argument_bits_length);
	}

	vty_out(vty, "functions:\n");
	for (ALL_LIST_ELEMENTS_RO(bgp->srv6_functions, node, func)) {
		vty_out(vty, "- sid: %pI6\n", &func->sid);
		vty_out(vty, "  locator: %s\n", func->locator_name);
	}

	vty_out(vty, "bgps:\n");
	for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, bgp)) {
		vty_out(vty, "- name: %s\n",
			bgp->name ? bgp->name : "default");

		vty_out(vty, "  vpn_policy[AFI_IP].tovpn_sid: %pI6\n",
			bgp->vpn_policy[AFI_IP].tovpn_sid);
		vty_out(vty, "  vpn_policy[AFI_IP6].tovpn_sid: %pI6\n",
			bgp->vpn_policy[AFI_IP6].tovpn_sid);
		vty_out(vty, "  per-vrf tovpn_sid: %pI6\n", bgp->tovpn_sid);
		vty_out(vty, "  srv6_unicast[AFI_IP].sid: %pI6\n", bgp->srv6_unicast[AFI_IP].sid);
		vty_out(vty, "  srv6_unicast[AFI_IP6].sid: %pI6\n", bgp->srv6_unicast[AFI_IP6].sid);
	}

	return CMD_SUCCESS;
}

DEFUN_YANG_NOSH (exit_address_family,
       exit_address_family_cmd,
       "exit-address-family",
       "Exit from Address Family configuration mode\n")
{
	if (vty->node == BGP_IPV4_NODE || vty->node == BGP_IPV4M_NODE
	    || vty->node == BGP_IPV4L_NODE || vty->node == BGP_VPNV4_NODE
	    || vty->node == BGP_IPV6_NODE || vty->node == BGP_IPV6M_NODE
	    || vty->node == BGP_IPV6L_NODE || vty->node == BGP_VPNV6_NODE
	    || vty->node == BGP_EVPN_NODE
	    || vty->node == BGP_FLOWSPECV4_NODE
	    || vty->node == BGP_FLOWSPECV6_NODE
	    || vty->node == BGP_LS_NODE
	    || vty->node == BGP_IPV4U_NODE
	    || vty->node == BGP_IPV6U_NODE)
		vty->node = BGP_NODE;
	return CMD_SUCCESS;
}

/* Recalculate bestpath and re-advertise a prefix */
static int bgp_clear_prefix(struct vty *vty, const char *view_name,
			    const char *ip_str, afi_t afi, safi_t safi,
			    struct prefix_rd *prd)
{
	int ret;
	struct prefix match;
	struct bgp_dest *dest;
	struct bgp_dest *rm;
	struct bgp *bgp;
	struct bgp_table *table;
	struct bgp_table *rib;

	/* BGP structure lookup. */
	if (view_name) {
		bgp = bgp_lookup_by_name(view_name);
		if (bgp == NULL) {
			vty_out(vty, "%% Can't find BGP instance %s\n",
				view_name);
			return CMD_WARNING;
		}
	} else {
		bgp = bgp_get_default();
		if (bgp == NULL) {
			vty_out(vty, "%% No BGP process is configured\n");
			return CMD_WARNING;
		}
	}

	/* Check IP address argument. */
	ret = str2prefix(ip_str, &match);
	if (!ret) {
		vty_out(vty, "%% address is malformed\n");
		return CMD_WARNING;
	}

	rib = bgp->rib[afi][safi];

	if (safi == SAFI_MPLS_VPN) {
		for (dest = bgp_table_top(rib); dest;
		     dest = bgp_route_next(dest)) {
			const struct prefix *dest_p = bgp_dest_get_prefix(dest);

			if (prd && memcmp(dest_p->u.val, prd->val, 8) != 0)
				continue;

			table = bgp_dest_get_bgp_table_info(dest);
			if (table == NULL)
				continue;

			rm = bgp_node_match(table, &match);
			if (rm != NULL) {
				const struct prefix *rm_p =
					bgp_dest_get_prefix(rm);

				if (rm_p->prefixlen == match.prefixlen) {
					SET_FLAG(rm->flags,
						 BGP_NODE_USER_CLEAR);
					bgp_process(bgp, rm,
						    bgp_dest_get_bgp_path_info(
							    rm),
						    afi, safi);
				}
				bgp_dest_unlock_node(rm);
			}
		}
	} else {
		dest = bgp_node_match(rib, &match);
		if (dest != NULL) {
			const struct prefix *dest_p = bgp_dest_get_prefix(dest);

			if (dest_p->prefixlen == match.prefixlen) {
				SET_FLAG(dest->flags, BGP_NODE_USER_CLEAR);
				bgp_process(bgp, dest,
					    bgp_dest_get_bgp_path_info(dest),
					    afi, safi);
			}
			bgp_dest_unlock_node(dest);
		}
	}

	return CMD_SUCCESS;
}

#ifdef DEV_BUILD
static struct bgp *bgp_test_instance(struct vty *vty, const char *vrf_name)
{
	struct bgp *bgp;

	if (vrf_name && !strmatch(vrf_name, VRF_DEFAULT_NAME))
		bgp = bgp_lookup_by_name(vrf_name);
	else
		bgp = bgp_get_default();

	if (!bgp)
		vty_out(vty, "%% BGP instance not found\n");

	return bgp;
}

DEFPY_HIDDEN(bgp_test_metaq_plug, bgp_test_metaq_plug_cmd,
	     "[no] bgp [vrf NAME$vrf_name] test metaq disable",
	     NO_STR
	     BGP_STR
	     VRF_CMD_HELP_STR
	     "Test command\n"
	     "Meta queue\n"
	     "Plug the meta queue (prevent best path processing)\n")
{
	struct bgp *bgp = bgp_test_instance(vty, vrf_name);

	if (!bgp)
		return CMD_WARNING;

	if (no)
		bgp_meta_queue_unplug(bgp);
	else
		bgp_meta_queue_plug(bgp);

	return CMD_SUCCESS;
}

DEFPY_HIDDEN(bgp_test_updates_plug, bgp_test_updates_plug_cmd,
	     "[no] bgp [vrf NAME$vrf_name] test updates disable [neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor]",
	     NO_STR
	     BGP_STR
	     VRF_CMD_HELP_STR
	     "Test command\n"
	     "Outgoing UPDATE messages\n"
	     "Plug outgoing UPDATE messages (prevent sending)\n"
	     NEIGHBOR_STR
	     NEIGHBOR_ADDR_STR2)
{
	struct bgp *bgp = bgp_test_instance(vty, vrf_name);
	struct peer *peer = NULL;

	if (!bgp)
		return CMD_WARNING;

	if (neighbor) {
		peer = peer_lookup_in_view(vty, bgp, neighbor, false);
		if (!peer)
			return CMD_WARNING;
	}

	if (no)
		bgp_updates_unplug(bgp, peer);
	else
		bgp_updates_plug(bgp, peer);

	return CMD_SUCCESS;
}
#endif

/* one clear bgp command to rule them all */
DEFUN(clear_ip_bgp_all, clear_ip_bgp_all_cmd,
      "clear [ip] bgp [<view|vrf> VIEWVRFNAME] [<ipv4|ipv6|l2vpn> [<unicast|multicast|vpn|labeled-unicast|flowspec|evpn|unreachability>]] <*|A.B.C.D$neighbor|X:X::X:X$neighbor|WORD$neighbor|ASNUM|external|peer-group PGNAME> [<soft [<in|out>]|in [prefix-filter]|out|message-stats|capabilities>]",
      CLEAR_STR IP_STR BGP_STR BGP_INSTANCE_HELP_STR BGP_AFI_HELP_STR BGP_AF_STR
	      BGP_SAFI_WITH_LABEL_HELP_STR
      "Address Family modifier\n"
      "Clear all peers\n"
      "BGP IPv4 neighbor to clear\n"
      "BGP IPv6 neighbor to clear\n"
      "BGP neighbor on interface to clear\n"
      "Clear peers with the AS number\n"
      "Clear all external peers\n"
      "Clear all members of peer-group\n"
      "BGP peer-group name\n" BGP_SOFT_STR BGP_SOFT_IN_STR BGP_SOFT_OUT_STR BGP_SOFT_IN_STR
      "Push out prefix-list ORF and do inbound soft reconfig\n" BGP_SOFT_OUT_STR
      "Reset message statistics\n"
      "Resend capabilities\n")
{
	char *vrf = NULL;

	afi_t afi = AFI_UNSPEC;
	safi_t safi = SAFI_UNSPEC;
	enum clear_sort clr_sort = clear_peer;
	enum bgp_clear_type clr_type;
	char *clr_arg = NULL;

	int idx = 0;

	/* clear [ip] bgp */
	if (argv_find(argv, argc, "ip", &idx))
		afi = AFI_IP;

	/* [<vrf> VIEWVRFNAME] */
	if (argv_find(argv, argc, "vrf", &idx)) {
		vrf = argv[idx + 1]->arg;
		idx += 2;
		if (vrf && strmatch(vrf, VRF_DEFAULT_NAME))
			vrf = NULL;
	} else if (argv_find(argv, argc, "view", &idx)) {
		/* [<view> VIEWVRFNAME] */
		vrf = argv[idx + 1]->arg;
		idx += 2;
	}
	/* ["BGP_AFI_CMD_STR" ["BGP_SAFI_CMD_STR"]] */
	if (argv_find_and_parse_afi(argv, argc, &idx, &afi))
		argv_find_and_parse_safi(argv, argc, &idx, &safi);

	/* <*|A.B.C.D|X:X::X:X|WORD|ASNUM|external|peer-group PGNAME> */
	if (argv_find(argv, argc, "*", &idx)) {
		clr_sort = clear_all;
	} else if (argv_find(argv, argc, "A.B.C.D", &idx)) {
		clr_sort = clear_peer;
		clr_arg = argv[idx]->arg;
	} else if (argv_find(argv, argc, "X:X::X:X", &idx)) {
		clr_sort = clear_peer;
		clr_arg = argv[idx]->arg;
	} else if (argv_find(argv, argc, "peer-group", &idx)) {
		clr_sort = clear_group;
		idx++;
		clr_arg = argv[idx]->arg;
	} else if (argv_find(argv, argc, "PGNAME", &idx)) {
		clr_sort = clear_peer;
		clr_arg = argv[idx]->arg;
	} else if (argv_find(argv, argc, "WORD", &idx)) {
		clr_sort = clear_peer;
		clr_arg = argv[idx]->arg;
	} else if (argv_find(argv, argc, "ASNUM", &idx)) {
		clr_sort = clear_as;
		clr_arg = argv[idx]->arg;
	} else if (argv_find(argv, argc, "external", &idx)) {
		clr_sort = clear_external;
	}

	/* [<soft [<in|out>]|in [prefix-filter]|out|message-stats|capabilities>] */
	if (argv_find(argv, argc, "soft", &idx)) {
		if (argv_find(argv, argc, "in", &idx)
		    || argv_find(argv, argc, "out", &idx))
			clr_type = strmatch(argv[idx]->text, "in")
					   ? BGP_CLEAR_SOFT_IN
					   : BGP_CLEAR_SOFT_OUT;
		else
			clr_type = BGP_CLEAR_SOFT_BOTH;
	} else if (argv_find(argv, argc, "in", &idx)) {
		clr_type = argv_find(argv, argc, "prefix-filter", &idx)
				   ? BGP_CLEAR_SOFT_IN_ORF_PREFIX
				   : BGP_CLEAR_SOFT_IN;
	} else if (argv_find(argv, argc, "out", &idx)) {
		clr_type = BGP_CLEAR_SOFT_OUT;
	} else if (argv_find(argv, argc, "message-stats", &idx)) {
		clr_type = BGP_CLEAR_MESSAGE_STATS;
	} else if (argv_find(argv, argc, "capabilities", &idx)) {
		clr_type = BGP_CLEAR_CAPABILITIES;
	} else
		clr_type = BGP_CLEAR_HARD;

	return bgp_clear_vty(vty, vrf, afi, safi, clr_sort, clr_type, clr_arg);
}

DEFUN (clear_ip_bgp_prefix,
       clear_ip_bgp_prefix_cmd,
       "clear [ip] bgp [<view|vrf> VIEWVRFNAME] prefix A.B.C.D/M",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Clear bestpath and re-advertise\n"
       "IPv4 prefix\n")
{
	char *vrf = NULL;
	char *prefix = NULL;

	int idx = 0;

	/* [<view|vrf> VIEWVRFNAME] */
	if (argv_find(argv, argc, "vrf", &idx)) {
		vrf = argv[idx + 1]->arg;
		idx += 2;
		if (vrf && strmatch(vrf, VRF_DEFAULT_NAME))
			vrf = NULL;
	} else if (argv_find(argv, argc, "view", &idx)) {
		/* [<view> VIEWVRFNAME] */
		vrf = argv[idx + 1]->arg;
		idx += 2;
	}

	prefix = argv[argc - 1]->arg;

	return bgp_clear_prefix(vty, vrf, prefix, AFI_IP, SAFI_UNICAST, NULL);
}

DEFUN (clear_bgp_ipv6_safi_prefix,
       clear_bgp_ipv6_safi_prefix_cmd,
       "clear [ip] bgp ipv6 "BGP_SAFI_CMD_STR" prefix X:X::X:X/M",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_AF_STR
       BGP_SAFI_HELP_STR
       "Clear bestpath and re-advertise\n"
       "IPv6 prefix\n")
{
	int idx_safi = 0;
	int idx_ipv6_prefix = 0;
	safi_t safi = SAFI_UNICAST;
	char *prefix = argv_find(argv, argc, "X:X::X:X/M", &idx_ipv6_prefix) ?
		argv[idx_ipv6_prefix]->arg : NULL;

	argv_find_and_parse_safi(argv, argc, &idx_safi, &safi);
	return bgp_clear_prefix(
		vty, NULL, prefix, AFI_IP6,
		safi, NULL);
}

DEFUN (clear_bgp_instance_ipv6_safi_prefix,
       clear_bgp_instance_ipv6_safi_prefix_cmd,
       "clear [ip] bgp <view|vrf> VIEWVRFNAME ipv6 "BGP_SAFI_CMD_STR" prefix X:X::X:X/M",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       BGP_AF_STR
       BGP_SAFI_HELP_STR
       "Clear bestpath and re-advertise\n"
       "IPv6 prefix\n")
{
	int idx_safi = 0;
	int idx_vrfview = 0;
	int idx_ipv6_prefix = 0;
	safi_t safi = SAFI_UNICAST;
	char *prefix = argv_find(argv, argc, "X:X::X:X/M", &idx_ipv6_prefix) ?
		argv[idx_ipv6_prefix]->arg : NULL;
	char *vrfview = NULL;

	/* [<view|vrf> VIEWVRFNAME] */
	if (argv_find(argv, argc, "vrf", &idx_vrfview)) {
		vrfview = argv[idx_vrfview + 1]->arg;
		if (vrfview && strmatch(vrfview, VRF_DEFAULT_NAME))
			vrfview = NULL;
	} else if (argv_find(argv, argc, "view", &idx_vrfview)) {
		/* [<view> VIEWVRFNAME] */
		vrfview = argv[idx_vrfview + 1]->arg;
	}
	argv_find_and_parse_safi(argv, argc, &idx_safi, &safi);

	return bgp_clear_prefix(
		vty, vrfview, prefix,
		AFI_IP6, safi, NULL);
}

DEFUN (show_bgp_views,
       show_bgp_views_cmd,
       "show [ip] bgp views",
       SHOW_STR
       IP_STR
       BGP_STR
       "Show the defined BGP views\n")
{
	struct list *inst = bm->bgp;
	struct listnode *node;
	struct bgp *bgp;

	vty_out(vty, "Defined BGP views:\n");
	for (ALL_LIST_ELEMENTS_RO(inst, node, bgp)) {
		/* Skip VRFs. */
		if (bgp->inst_type == BGP_INSTANCE_TYPE_VRF)
			continue;
		vty_out(vty, "\t%s (AS%s)\n", bgp->name ? bgp->name : "(null)",
			bgp->as_pretty);
	}

	return CMD_SUCCESS;
}

static inline void calc_peers_cfgd_estbd(struct bgp *bgp, int *peers_cfgd,
					 int *peers_estbd)
{
	struct peer *peer;
	struct listnode *node;

	*peers_cfgd = *peers_estbd = 0;
	for (ALL_LIST_ELEMENTS_RO(bgp->peer, node, peer)) {
		if (!peer_is_config_node(peer))
			continue;
		(*peers_cfgd)++;
		if (peer_established(peer->connection))
			(*peers_estbd)++;
	}
}

static void print_bgp_vrfs_listen_range(struct vty *vty, struct bgp *bgp,
				      json_object *json)
{
	afi_t afi;
	struct prefix *range;
	struct peer_group *group;
	struct listnode *node, *nnode, *rnode, *nrnode;

	/* listen range and limit for dynamic BGP neighbors info */
	if (json) {
		if (bgp->dynamic_neighbors_limit != BGP_DYNAMIC_NEIGHBORS_LIMIT_DEFAULT)
			json_object_int_add(json, "dynamicNeighLimit",
					    bgp->dynamic_neighbors_limit);

		json_object *json_listen_range = NULL, *json_listen_range_list = NULL;

		json_listen_range_list = json_object_new_object();
		for (ALL_LIST_ELEMENTS(bgp->group, node, nnode, group)) {
			for (afi = AFI_IP; afi < AFI_MAX; afi++) {
				for (ALL_LIST_ELEMENTS(group->listen_range[afi], rnode, nrnode,
						       range)) {
					json_listen_range = json_object_new_object();
					json_object_string_add(json_listen_range, "peerGroup",
							       group->name);
					json_object_object_addf(json_listen_range_list,
								json_listen_range, "%pFX", range);
				}
			}
		}
		json_object_object_add(json, "dynamicNeighListen", json_listen_range_list);
	} else {
		if (bgp->dynamic_neighbors_limit != BGP_DYNAMIC_NEIGHBORS_LIMIT_DEFAULT)
			vty_out(vty, "BGP Listen Limit: %d\n", bgp->dynamic_neighbors_limit);

		for (ALL_LIST_ELEMENTS(bgp->group, node, nnode, group)) {
			for (afi = AFI_IP; afi < AFI_MAX; afi++) {
				for (ALL_LIST_ELEMENTS(group->listen_range[afi], rnode, nrnode,
						       range)) {
					vty_out(vty, "BGP Listen Range %pFX peer-group %s\n",
						range, group->name);
				}
			}
		}
	}
}

static void print_bgp_vrfs_confederation(struct vty *vty, struct bgp *bgp,
					 json_object *json)
{
	if (json) {
		if (CHECK_FLAG(bgp->config, BGP_CONFIG_CONFEDERATION))
			json_object_int_add(json, "confederationId", bgp->confed_id);
		if (bgp->confed_peers_cnt > 0) {
			int i;
			json_object *json_confed_peers_list = NULL;

			json_confed_peers_list = json_object_new_array();
			for (i = 0; i < bgp->confed_peers_cnt; i++) {
				json_object_array_add(json_confed_peers_list,
						      json_object_new_int(bgp->confed_peers[i].as));
			}
			json_object_object_add(json, "confederationMemberList",
					       json_confed_peers_list);
		}
	} else {
		if (CHECK_FLAG(bgp->config, BGP_CONFIG_CONFEDERATION))
			vty_out(vty, "BGP Confederation Identifier: %u\n", bgp->confed_id);
		if (bgp->confed_peers_cnt > 0) {
			int i;

			vty_out(vty, "BGP Confederation Peers: ");
			for (i = 0; i < bgp->confed_peers_cnt; i++)
				vty_out(vty, " %u", bgp->confed_peers[i].as);

			vty_out(vty, "\n");
		}
	}
}

static void print_bgp_vrfs_timers(struct vty *vty, struct bgp *bgp, json_object *json)
{
	if (json) {
		if (bgp->default_keepalive != SAVE_BGP_KEEPALIVE ||
		    bgp->default_holdtime != SAVE_BGP_HOLDTIME) {
			json_object_int_add(json, "keepaliveTimer", bgp->default_keepalive);
			json_object_int_add(json, "holdTimer", bgp->default_holdtime);
			/* SendQ stall teardown threshold (bgp_packet.c): 2 * holdtime */
			json_object_int_add(json, "sendHoldTimer",
					    bgp->default_holdtime * 2);
		}
		if (bgp->condition_check_period != DEFAULT_CONDITIONAL_ROUTES_POLL_TIME)
			json_object_int_add(json, "condAdvertismentTimer",
					    bgp->condition_check_period);

	} else {
		if (bgp->default_keepalive != SAVE_BGP_KEEPALIVE ||
		    bgp->default_holdtime != SAVE_BGP_HOLDTIME)
			vty_out(vty,
				"BGP Timers Keepalive: %u Holdtime: %u Send-Hold (2x hold, SendQ): %u\n",
				bgp->default_keepalive, bgp->default_holdtime,
				bgp->default_holdtime * 2);
		if (bgp->condition_check_period != DEFAULT_CONDITIONAL_ROUTES_POLL_TIME)
			vty_out(vty, "BGP Conditional Advertisement Timer: %u\n",
				bgp->condition_check_period);
	}
}

static void print_bgp_vrfs_route_targets(struct vty *vty, struct bgp *bgp, json_object *json)
{
	struct bgp_evpn_rt_config *rt_config = bgp->vrf_route_target_config;

	/* import and export route-target info */
	if (json) {
		if (CHECK_FLAG(bgp->vrf_flags, BGP_VRF_RD_CFGD))
			json_object_string_add(json, "rd", bgp->vrf_prd_pretty);

		json_object_boolean_add(json, "defaultOriginateV4",
					CHECK_FLAG(bgp->af_flags[AFI_L2VPN][SAFI_EVPN],
						   BGP_L2VPN_EVPN_DEFAULT_ORIGINATE_IPV4));

		json_object_boolean_add(json, "defaultOriginateV6",
					CHECK_FLAG(bgp->af_flags[AFI_L2VPN][SAFI_EVPN],
						   BGP_L2VPN_EVPN_DEFAULT_ORIGINATE_IPV6));

		if (CHECK_FLAG(bgp->af_flags[AFI_L2VPN][SAFI_EVPN],
			       BGP_L2VPN_EVPN_ADV_IPV4_UNICAST)) {
			if (bgp->adv_cmd_rmap[AFI_IP][SAFI_UNICAST].name)
				json_object_string_add(json, "advertiseV4UnicastRoutemap",
						       bgp->adv_cmd_rmap[AFI_IP][SAFI_UNICAST].name);
		}

		if (CHECK_FLAG(bgp->af_flags[AFI_L2VPN][SAFI_EVPN],
			       BGP_L2VPN_EVPN_ADV_IPV6_UNICAST)) {
			if (bgp->adv_cmd_rmap[AFI_IP6][SAFI_UNICAST].name)
				json_object_string_add(json, "advertiseV6UnicastRoutemap",
						       bgp->adv_cmd_rmap[AFI_IP6][SAFI_UNICAST].name);
		}

		if (bgp_evpn_vrf_has_manual_import_rt_cfgd(bgp)) {
			char rt_buf[RT_ADDRSTRLEN];
			struct bgp_evpn_cfgd_rt *cfgd_rt;
			json_object *json_import_rt_list = NULL;

			json_import_rt_list = json_object_new_array();
			frr_each (bgp_evpn_cfgd_rt_slu, &rt_config->cfgd_import, cfgd_rt) {
				bgp_evpn_format_cfgd_rt(rt_buf, sizeof(rt_buf), cfgd_rt);
				json_object_array_add(json_import_rt_list,
						      json_object_new_string(rt_buf));
			}
			/* import route-target auto */
			if (bgp_evpn_vrf_has_auto_import_rt_cfgd(bgp)) {
				json_object_array_add(json_import_rt_list,
						      json_object_new_string("auto"));
			}
			json_object_object_add(json, "routeTargetImport", json_import_rt_list);
		}

		/* export route-target */
		if (bgp_evpn_vrf_has_manual_export_rt_cfgd(bgp)) {
			char rt_buf[RT_ADDRSTRLEN];
			struct bgp_evpn_cfgd_rt *cfgd_rt;
			json_object *json_export_rt_list = NULL;

			json_export_rt_list = json_object_new_array();
			frr_each (bgp_evpn_cfgd_rt_slu, &rt_config->cfgd_export, cfgd_rt) {
				bgp_evpn_format_cfgd_rt(rt_buf, sizeof(rt_buf), cfgd_rt);
				json_object_array_add(json_export_rt_list,
						      json_object_new_string(rt_buf));
			}
			/* export route-target auto */
			if (bgp_evpn_vrf_has_auto_export_rt_cfgd(bgp)) {
				json_object_array_add(json_export_rt_list,
						      json_object_new_string("auto"));
			}
			json_object_object_add(json, "routeTargetExport", json_export_rt_list);
		}
	} else {
		if (CHECK_FLAG(bgp->vrf_flags, BGP_VRF_RD_CFGD))
			vty_out(vty, "RD %s\n", bgp->vrf_prd_pretty);

		if (CHECK_FLAG(bgp->af_flags[AFI_L2VPN][SAFI_EVPN],
			       BGP_L2VPN_EVPN_DEFAULT_ORIGINATE_IPV4))
			vty_out(vty, "  default-originate ipv4\n");

		if (CHECK_FLAG(bgp->af_flags[AFI_L2VPN][SAFI_EVPN],
			       BGP_L2VPN_EVPN_DEFAULT_ORIGINATE_IPV6))
			vty_out(vty, "  default-originate ipv6\n");

		if (CHECK_FLAG(bgp->af_flags[AFI_L2VPN][SAFI_EVPN],
			       BGP_L2VPN_EVPN_ADV_IPV4_UNICAST)) {
			if (bgp->adv_cmd_rmap[AFI_IP][SAFI_UNICAST].name)
				vty_out(vty, "  advertise ipv4 unicast route-map %s\n",
					bgp->adv_cmd_rmap[AFI_IP][SAFI_UNICAST].name);
		}

		if (CHECK_FLAG(bgp->af_flags[AFI_L2VPN][SAFI_EVPN],
			       BGP_L2VPN_EVPN_ADV_IPV6_UNICAST)) {
			if (bgp->adv_cmd_rmap[AFI_IP6][SAFI_UNICAST].name)
				vty_out(vty, "  advertise ipv6 unicast route-map %s\n",
					bgp->adv_cmd_rmap[AFI_IP6][SAFI_UNICAST].name);
		}

		if (bgp_evpn_vrf_has_manual_import_rt_cfgd(bgp)) {
			char rt_buf[RT_ADDRSTRLEN];
			struct bgp_evpn_cfgd_rt *cfgd_rt;

			vty_out(vty, "Route Target Import\n");
			frr_each (bgp_evpn_cfgd_rt_slu, &rt_config->cfgd_import, cfgd_rt) {
				bgp_evpn_format_cfgd_rt(rt_buf, sizeof(rt_buf), cfgd_rt);
				vty_out(vty, "   %s\n", rt_buf);
			}
		}
		/* import route-target auto */
		if (bgp_evpn_vrf_has_auto_import_rt_cfgd(bgp))
			vty_out(vty, "   auto\n");

		/* export route-target info */
		if (bgp_evpn_vrf_has_manual_export_rt_cfgd(bgp)) {
			char rt_buf[RT_ADDRSTRLEN];
			struct bgp_evpn_cfgd_rt *cfgd_rt;

			vty_out(vty, "Route Target Export\n");
			frr_each (bgp_evpn_cfgd_rt_slu, &rt_config->cfgd_export, cfgd_rt) {
				bgp_evpn_format_cfgd_rt(rt_buf, sizeof(rt_buf), cfgd_rt);
				vty_out(vty, "   %s\n", rt_buf);
			}
		}
		/* export route-target auto */
		if (bgp_evpn_vrf_has_auto_export_rt_cfgd(bgp))
			vty_out(vty, "   auto\n");
	}
}

static void print_bgp_vrfs(struct bgp *bgp, struct vty *vty, json_object *json,
			   const char *type)
{
	int peers_cfg, peers_estb;
	afi_t afi;
	safi_t safi = SAFI_UNICAST;

	calc_peers_cfgd_estbd(bgp, &peers_cfg, &peers_estb);
	enum global_mode gr_mode = bgp_global_gr_mode_get(bgp);

	if (json) {
		int64_t vrf_id_ui = (bgp->vrf_id == VRF_UNKNOWN)
					    ? -1
					    : (int64_t)bgp->vrf_id;

		json_object_string_add(json, "type", type);
		json_object_int_add(json, "vrfId", vrf_id_ui);
		json_object_string_addf(json, "routerId", "%pI4",
					&bgp->router_id);
		json_object_int_add(json, "as", bgp->as);
		json_object_int_add(json, "numConfiguredPeers", peers_cfg);
		json_object_int_add(json, "numEstablishedPeers", peers_estb);
		json_object_int_add(json, "l3vni", bgp->l3vni);
		json_object_string_addf(json, "rmac", "%pEA", &bgp->rmac);
		json_object_string_add(
			json, "interface",
			ifindex2ifname(bgp->l3vni_svi_ifindex, bgp->vrf_id));

		if (CHECK_FLAG(bm->flags, BM_FLAG_GRACEFUL_RESTART)) {
			struct graceful_restart_info *gr_info;

			json_object *json_gr = NULL;
			json_object *json_grs = NULL;

			json_grs = json_object_new_array();

			for (afi = AFI_IP; afi <= AFI_IP6; afi++) {
				json_gr = json_object_new_object();
				json_object_string_add(json_gr, "addressFamily",
						       get_afi_safi_str(afi, safi, false));
				gr_info = &(bgp->gr_info[afi][safi]);
				json_object_boolean_add(json_gr, "grEnabled", gr_info->af_enabled);
				json_object_boolean_add(json_gr, "grPathSelectionDeferral",
							event_is_scheduled(
								gr_info->t_select_deferral));
				if (event_is_scheduled(gr_info->t_select_deferral))
					json_object_int_add(json_gr, "grDeferralRemainingTimeSec",
							    event_timer_remain_second(
								    gr_info->t_select_deferral));
				json_object_array_add(json_grs, json_gr);
			}
			json_object_boolean_add(json, "grRouteSyncPending",
						bgp->gr_route_sync_pending);
			json_object_object_add(json, "grs", json_grs);
		}
		json_object_int_add(json, "grRestartTime", bgp->restart_time);
		json_object_int_add(json, "grStalePathTime", bgp->stalepath_time);
		json_object_int_add(json, "grSelectDeferTime", bgp->select_defer_time);
		json_object_string_add(json, "grMode", bgp_global_gr_mode_str[gr_mode]);
		json_object_boolean_add(json, "waitForFibSet",
					CHECK_FLAG(bgp->flags, BGP_FLAG_SUPPRESS_FIB_PENDING));
		json_object_boolean_add(json, "gShutEnabled",
					CHECK_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_SHUTDOWN));

		/* BGP cluster ID. */
		if (CHECK_FLAG(bgp->config, BGP_CONFIG_CLUSTER_ID))
			json_object_string_addf(json, "bgpClusterId", "%pI4", &bgp->cluster_id);
		/* BGP route-reflector allow-outbound-policy. */
		json_object_boolean_add(json, "rrAllowOutboundPolicy",
					CHECK_FLAG(bgp->flags, BGP_FLAG_RR_ALLOW_OUTBOUND_POLICY));
		/* BGP client-to-client reflection. */
		json_object_boolean_add(json, "noClientToClientReflection",
					CHECK_FLAG(bgp->flags, BGP_FLAG_NO_CLIENT_TO_CLIENT));

		/* BGP confederation, then timers (JSON key order matches prior output) */
		print_bgp_vrfs_confederation(vty, bgp, json);
		print_bgp_vrfs_timers(vty, bgp, json);

		/* listen range and limit for dynamic BGP neighbors info */
		print_bgp_vrfs_listen_range(vty, bgp, json);

		/* import and export route-target info */
		print_bgp_vrfs_route_targets(vty, bgp, json);

		/* address-family info */
		json_object *json_addr = NULL, *json_af = NULL;

		json_af = json_object_new_object();
		for (afi = AFI_IP; afi <= AFI_IP6; afi++) {
			json_addr = json_object_new_object();
			json_object *json_aggregate = NULL, *json_agg = NULL, *json_network = NULL,
				    *json_static = NULL;
			struct bgp_dest *dest;
			const struct prefix *p;
			struct bgp_aggregate *bgp_aggregate;
			struct bgp_static *bgp_static;

			json_aggregate = json_object_new_object();
			json_network = json_object_new_object();

			/* Import VRF route-map info */
			if (bgp->vpn_policy[afi].rmap_name[BGP_VPN_POLICY_DIR_FROMVPN]) {
				if (CHECK_FLAG(bgp->af_flags[afi][SAFI_UNICAST],
					       BGP_CONFIG_VRF_TO_VRF_IMPORT))
					json_object_string_add(json_addr, "importVrfRouteMap",
							       bgp->vpn_policy[afi].rmap_name
								       [BGP_VPN_POLICY_DIR_FROMVPN]);
				else
					json_object_string_add(json_addr, "importVpnRouteMap",
							       bgp->vpn_policy[afi].rmap_name
								       [BGP_VPN_POLICY_DIR_FROMVPN]);
			}
			/* avertise origin, nhg per origin and tablemap info */
			json_object_string_add(json_addr, "afi",
					       get_afi_safi_str(afi, safi, false));
			if (bgp->table_map[afi][safi].name)
				json_object_string_add(json_addr, "tableMap",
						       bgp->table_map[afi][safi].name);

			/* bgp multipath info */
			if (bgp->maxpaths[afi][safi].maxpaths_ebgp != multipath_num)
				json_object_int_add(json_addr, "ebgpMaximumPaths",
						    bgp->maxpaths[afi][safi].maxpaths_ebgp);
			if (bgp->maxpaths[afi][safi].maxpaths_ibgp != multipath_num ||
			    bgp->maxpaths[afi][safi].same_clusterlen) {
				json_object_int_add(json_addr, "ibgpMaximumPaths",
						    bgp->maxpaths[afi][safi].maxpaths_ibgp);
				json_object_boolean_add(json_addr, "equalClusterLength",
							bgp->maxpaths[afi][safi].same_clusterlen);
			}

			/* bgp distance info */
			if (bgp->distance_ebgp[afi][safi])
				json_object_int_add(json_addr, "ebgpDistance",
						    bgp->distance_ebgp[afi][safi]);
			if (bgp->distance_ibgp[afi][safi])
				json_object_int_add(json_addr, "ibgpDistance",
						    bgp->distance_ibgp[afi][safi]);
			if (bgp->distance_local[afi][safi])
				json_object_int_add(json_addr, "localDistance",
						    bgp->distance_local[afi][safi]);

			/* Network configuration (walk static_routes; RIB holds paths, not bgp_static). */
			if (bgp->static_routes[afi][safi]) {
				for (dest = bgp_table_top(bgp->static_routes[afi][safi]);
				     dest; dest = bgp_route_next(dest)) {
					if (!bgp_dest_has_bgp_path_info_data(dest))
						continue;

					bgp_static = bgp_dest_get_bgp_static_info(dest);
					if (bgp_static == NULL)
						continue;

					p = bgp_dest_get_prefix(dest);
					json_static = json_object_new_object();

					if (bgp_static->rmap.name)
						json_object_string_add(json_static, "routeMap",
								       bgp_static->rmap.name);

					json_object_object_addf(json_network, json_static,
								"%pFX", p);
				}
			}
			json_object_object_add(json_addr, "network", json_network);

			/* Aggregate-address info */
			if (bgp->aggregate[afi][safi]) {
				for (dest = bgp_table_top(bgp->aggregate[afi][safi]); dest;
				     dest = bgp_route_next(dest)) {
					bgp_aggregate =
						bgp_dest_get_bgp_aggregate_info(dest);
					if (bgp_aggregate == NULL)
						continue;

					p = bgp_dest_get_prefix(dest);
					json_agg = json_object_new_object();

					if (bgp_aggregate->as_set)
						json_object_boolean_add(json_agg, "asSet",
									bgp_aggregate->as_set);
					if (bgp_aggregate->summary_only)
						json_object_boolean_add(json_agg, "summaryOnly",
									bgp_aggregate->summary_only);
					if (bgp_aggregate->rmap.name)
						json_object_string_add(json_agg, "routeMap",
								       bgp_aggregate->rmap.name);

					json_object_object_addf(json_aggregate, json_agg,
								"%pFX", p);
				}
			}
			json_object_object_add(json_addr, "aggregateAddress",
					       json_aggregate);

			json_object_object_add(json_af, get_afi_safi_str(afi, safi, true),
					       json_addr);
		}
		json_object_object_add(json, "addressFamilyInfo", json_af);
	}
}

/* Static network / aggregate lines for `show bgp vrfs <name>` (plain text). */
static void print_bgp_vrfs_detail_network_lines(struct vty *vty, struct bgp *bgp,
						afi_t afi, safi_t safi)
{
	struct bgp_dest *dest;
	struct bgp_static *bgp_static;
	const struct prefix *p;

	if (!bgp->static_routes[afi][safi])
		return;

	for (dest = bgp_table_top(bgp->static_routes[afi][safi]); dest;
	     dest = bgp_route_next(dest)) {
		if (!bgp_dest_has_bgp_path_info_data(dest))
			continue;

		bgp_static = bgp_dest_get_bgp_static_info(dest);
		if (!bgp_static)
			continue;

		p = bgp_dest_get_prefix(dest);
		vty_out(vty, "   network %pFX", p);
		if (bgp_static->rmap.name)
			vty_out(vty, " route-map %s", bgp_static->rmap.name);
		vty_out(vty, "\n");
	}
}

static void print_bgp_vrfs_detail_aggregate_lines(struct vty *vty, struct bgp *bgp,
						  afi_t afi, safi_t safi)
{
	struct bgp_dest *dest;
	struct bgp_aggregate *bgp_aggregate;
	const struct prefix *p;

	if (!bgp->aggregate[afi][safi])
		return;

	for (dest = bgp_table_top(bgp->aggregate[afi][safi]); dest;
	     dest = bgp_route_next(dest)) {
		bgp_aggregate = bgp_dest_get_bgp_aggregate_info(dest);
		if (!bgp_aggregate)
			continue;

		p = bgp_dest_get_prefix(dest);
		vty_out(vty, "   aggregate-address %pFX", p);
		if (bgp_aggregate->as_set)
			vty_out(vty, " as-set");
		if (bgp_aggregate->summary_only)
			vty_out(vty, " summary-only");
		if (bgp_aggregate->rmap.name)
			vty_out(vty, " route-map %s", bgp_aggregate->rmap.name);
		vty_out(vty, "\n");
	}
}

static int show_bgp_vrfs_detail_common(struct vty *vty, struct bgp *bgp,
				       json_object *json, const char *name,
				       const char *type, bool use_vrf)
{
	int peers_cfg, peers_estb;
	afi_t afi;
	safi_t safi = SAFI_UNICAST;

	calc_peers_cfgd_estbd(bgp, &peers_cfg, &peers_estb);

	if (use_vrf) {
		enum global_mode gr_mode = bgp_global_gr_mode_get(bgp);

		if (json) {
			print_bgp_vrfs(bgp, vty, json, type);
		} else {
			vty_out(vty, "BGP instance %s VRF id %d\n",
				bgp->name_pretty,
				bgp->vrf_id == VRF_UNKNOWN ? -1
							   : (int)bgp->vrf_id);
			vty_out(vty, "Router Id %pI4\n", &bgp->router_id);
			vty_out(vty, "AS number %u\n", bgp->as);
			vty_out(vty,
				"Num Configured Peers %d, Established %d\n",
				peers_cfg, peers_estb);
			vty_out(vty, "Global graceful restart mode is %s\n",
				bgp_global_gr_mode_str[gr_mode]);
			if (bgp->l3vni) {
				vty_out(vty,
					"L3VNI %u, L3VNI-SVI %s, Router MAC %pEA\n",
					bgp->l3vni,
					ifindex2ifname(bgp->l3vni_svi_ifindex,
						       bgp->vrf_id),
					&bgp->rmac);
			}
			if (CHECK_FLAG(bm->flags, BM_FLAG_GRACEFUL_RESTART)) {
				struct graceful_restart_info *gr_info;

				for (afi = AFI_IP; afi <= AFI_IP6; afi++) {
					vty_out(vty, "For address-family %s:\n",
						get_afi_safi_str(afi, safi, false));
					gr_info = &(bgp->gr_info[afi][safi]);
					vty_out(vty, "  GR enabled %s Path Selection Deferral %s\n",
						gr_info->af_enabled ? "YES" : "NO",
						event_is_scheduled(gr_info->t_select_deferral)
							? "DONE"
							: "IN-PROGRESS");
					if (event_is_scheduled(gr_info->t_select_deferral))
						vty_out(vty,
							"  Path selection deferral timer running, remaining time %lds\n",
							event_timer_remain_second(
								gr_info->t_select_deferral));
				}
				vty_out(vty, "Route sync with zebra %s\n",
					bgp->gr_route_sync_pending ? "pending" : "completed");
			}
			vty_out(vty, "GR Restart Time Configured: %ds\n", bgp->restart_time);
			vty_out(vty, "GR Stale Path Time Configured: %ds\n", bgp->stalepath_time);
			vty_out(vty, "GR Select Defer Time Configured: %ds\n",
				bgp->select_defer_time);
			vty_out(vty, "Wait for install (FIB suppress pending) is set: %s\n",
				CHECK_FLAG(bgp->flags, BGP_FLAG_SUPPRESS_FIB_PENDING) ? "YES"
										      : "NO");
			vty_out(vty, "BGP Graceful Shutdown is enabled: %s\n",
				CHECK_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_SHUTDOWN) ? "YES" : "NO");

			/* BGP cluster ID. */
			if (CHECK_FLAG(bgp->config, BGP_CONFIG_CLUSTER_ID))
				vty_out(vty, "BGP cluster-id %pI4\n", &bgp->cluster_id);

			/* BGP route-reflector allow-outbound-policy. */
			if (CHECK_FLAG(bgp->flags, BGP_FLAG_RR_ALLOW_OUTBOUND_POLICY))
				vty_out(vty, "BGP route-reflector allow-outbound-policy\n");

			/* BGP client-to-client reflection. */
			if (CHECK_FLAG(bgp->flags, BGP_FLAG_NO_CLIENT_TO_CLIENT))
				vty_out(vty, "No BGP client-to-client reflection\n");

			/* BGP timers, then confederation (text line order matches prior output) */
			print_bgp_vrfs_timers(vty, bgp, NULL);
			print_bgp_vrfs_confederation(vty, bgp, NULL);

			/* listen range and limit for dynamic BGP neighbors info */
			print_bgp_vrfs_listen_range(vty, bgp, NULL);

			/* import export route-target info */
			print_bgp_vrfs_route_targets(vty, bgp, NULL);

			/* address-family info */
			for (afi = AFI_IP; afi <= AFI_IP6; afi++) {
				vty_out(vty, "For address-family %s:\n",
					get_afi_safi_str(afi, safi, false));
				/* Import VRF route-map info */
				if (bgp->vpn_policy[afi].rmap_name[BGP_VPN_POLICY_DIR_FROMVPN]) {
					if (CHECK_FLAG(bgp->af_flags[afi][SAFI_UNICAST],
						       BGP_CONFIG_VRF_TO_VRF_IMPORT))
						vty_out(vty, "   Import Vrf Route-map %s\n",
							bgp->vpn_policy[afi].rmap_name
								[BGP_VPN_POLICY_DIR_FROMVPN]);
					else
						vty_out(vty, "   Import Vpn Route-map %s\n",
							bgp->vpn_policy[afi].rmap_name
								[BGP_VPN_POLICY_DIR_FROMVPN]);
				}

				if (bgp->table_map[afi][safi].name)
					vty_out(vty, "   BGP Tablemap %s\n",
						bgp->table_map[afi][safi].name);

				/* bgp multipath configuration */
				if (bgp->maxpaths[afi][safi].maxpaths_ebgp != multipath_num) {
					vty_out(vty, "   EBGP Maximumpaths %d\n",
						bgp->maxpaths[afi][safi].maxpaths_ebgp);
				}
				if (bgp->maxpaths[afi][safi].maxpaths_ibgp != multipath_num ||
				    bgp->maxpaths[afi][safi].same_clusterlen) {
					vty_out(vty, "   IBGP Maximumpaths %d\n",
						bgp->maxpaths[afi][safi].maxpaths_ibgp);
					if (bgp->maxpaths[afi][safi].same_clusterlen)
						vty_out(vty, "   Equal Cluster Length: %s\n",
							bgp->maxpaths[afi][safi].same_clusterlen
								? "YES"
								: "NO");
				}

				/* bgp distance configuration */
				if (bgp->distance_ebgp[afi][safi])
					vty_out(vty, "   BGP Distance Ebgp %d\n",
						bgp->distance_ebgp[afi][safi]);
				if (bgp->distance_ibgp[afi][safi])
					vty_out(vty, "   BGP Distance Ibgp %d\n",
						bgp->distance_ibgp[afi][safi]);
				if (bgp->distance_local[afi][safi])
					vty_out(vty, "   BGP Distance Local %d\n",
						bgp->distance_local[afi][safi]);

				/* Network configuration (walk static_routes; RIB holds paths, not bgp_static). */
				print_bgp_vrfs_detail_network_lines(vty, bgp, afi, safi);
				vty_out(vty, "\n");

				/* Aggregate-address info */
				print_bgp_vrfs_detail_aggregate_lines(vty, bgp, afi, safi);
				vty_out(vty, "\n");
			}
		}
	} else {
		if (json) {
			print_bgp_vrfs(bgp, vty, json, type);
		} else {
			vty_out(vty, "%4s  %-5d  %-16pI4  %-9u  %-10u  %-37s\n",
				type,
				bgp->vrf_id == VRF_UNKNOWN ? -1
							   : (int)bgp->vrf_id,
				&bgp->router_id, peers_cfg, peers_estb, name);
			vty_out(vty, "%11s  %-16u  %-21pEA  %-20s\n", " ",
				bgp->l3vni, &bgp->rmac,
				ifindex2ifname(bgp->l3vni_svi_ifindex,
					       bgp->vrf_id));
		}
	}

	return CMD_SUCCESS;
}

DEFPY (show_bgp_vrfs,
       show_bgp_vrfs_cmd,
       "show [ip] bgp vrfs [<VRFNAME$vrf_name>] [json]",
       SHOW_STR
       IP_STR
       BGP_STR
       "Show BGP VRFs\n"
       "Specific VRF name\n"
       JSON_STR)
{
	struct list *inst = bm->bgp;
	struct listnode *node;
	struct bgp *bgp;
	bool uj = use_json(argc, argv);
	json_object *json = NULL;
	json_object *json_vrfs = NULL;
	json_object *json_vrf = NULL;
	int count = 0;
	const char *name = vrf_name;
	const char *type;

	if (uj)
		json = json_object_new_object();

	if (name) {
		if (strmatch(name, VRF_DEFAULT_NAME)) {
			bgp = bgp_get_default();
			type = "DFLT";
		} else {
			bgp = bgp_lookup_by_name(name);
			type = "VRF";
		}
		if (!bgp) {
			if (uj)
				vty_json(vty, json);
			else
				vty_out(vty,
					"%% Specified BGP instance not found\n");

			return CMD_WARNING;
		}
	}

	if (vrf_name) {
		if (uj)
			json_vrf = json_object_new_object();

		show_bgp_vrfs_detail_common(vty, bgp, json_vrf, name, type,
					    true);

		if (uj) {
			json_object_object_add(json, name, json_vrf);
			vty_json(vty, json);
		}

		return CMD_SUCCESS;
	}

	if (uj)
		json_vrfs = json_object_new_object();

	for (ALL_LIST_ELEMENTS_RO(inst, node, bgp)) {
		const char *bname;

		/* Skip Views. */
		if (bgp->inst_type == BGP_INSTANCE_TYPE_VIEW)
			continue;

		/* Skip hidden instances (no RIB/aggregate tables allocated). */
		if (IS_BGP_INSTANCE_HIDDEN(bgp))
			continue;

		count++;
		if (!uj && count == 1) {
			vty_out(vty,
				"%4s  %-5s  %-16s  %9s  %10s  %-37s\n",
				"Type", "Id", "routerId", "#PeersCfg",
				"#PeersEstb", "Name");
			vty_out(vty, "%11s  %-16s  %-21s  %-6s\n", " ",
				"L3-VNI", "RouterMAC", "Interface");
		}
		if (uj)
			json_vrf = json_object_new_object();

		if (bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT) {
			bname = VRF_DEFAULT_NAME;
			type = "DFLT";
		} else {
			bname = bgp->name;
			type = "VRF";
		}

		show_bgp_vrfs_detail_common(vty, bgp, json_vrf, bname, type,
					    false);

		if (uj)
			json_object_object_add(json_vrfs, bname, json_vrf);
	}

	if (uj) {
		json_object_object_add(json, "vrfs", json_vrfs);
		json_object_int_add(json, "totalVrfs", count);
		vty_json(vty, json);
	} else {
		if (count)
			vty_out(vty,
				"\nTotal number of VRFs (including default): %d\n",
				count);
	}

	return CMD_SUCCESS;
}

DEFPY(show_bgp_router,
      show_bgp_router_cmd,
      "show bgp router [json]",
      SHOW_STR
      BGP_STR
      "Overall BGP information\n"
      JSON_STR)
{
	char timebuf[MONOTIME_STRLEN];
	time_t unix_timestamp;
	bool uj = use_json(argc, argv);
	json_object *json = NULL;
	uint32_t total_established = 0;
	struct listnode *node;
	struct bgp *bgp;

	if (uj)
		json = json_object_new_object();

	time_to_string(bm->start_time, timebuf);

	if (uj) {
		unix_timestamp = time(NULL) - (monotime(NULL) - bm->start_time);
		json_object_int_add(json, "bgpStartedAt", unix_timestamp);
		json_object_boolean_add(json, "bgpStartedGracefully",
					CHECK_FLAG(bm->flags, BM_FLAG_GRACEFUL_RESTART));
	}

	if (CHECK_FLAG(bm->flags, BM_FLAG_GRACEFUL_RESTART)) {
		if (!uj)
			vty_out(vty, "BGP started gracefully at %s", timebuf);
		else
			json_object_boolean_add(json, "grComplete",
						CHECK_FLAG(bm->flags, BM_FLAG_GR_COMPLETE));

		if (CHECK_FLAG(bm->flags, BM_FLAG_GR_COMPLETE)) {
			time_to_string(bm->gr_completion_time, timebuf);
			if (uj) {
				unix_timestamp = time(NULL) -
						 (monotime(NULL) - bm->gr_completion_time);
				json_object_int_add(json, "grCompletedAt", unix_timestamp);
			} else
				vty_out(vty, "Graceful restart completed at %s", timebuf);
		} else {
			if (!uj)
				vty_out(vty, "Graceful restart is in progress\n");
		}
	} else {
		if (!uj)
			vty_out(vty, "BGP started at %s", timebuf);
	}

	if (uj) {
		json_object_boolean_add(json, "bgpGshutEnabled",
					CHECK_FLAG(bm->flags, BM_FLAG_GRACEFUL_SHUTDOWN));
	} else {
		vty_out(vty, "BGP Graceful Shutdown is %s\n",
			CHECK_FLAG(bm->flags, BM_FLAG_GRACEFUL_SHUTDOWN) ? "enabled" : "disabled");
	}

	/* Sum established peers across all BGP instances */
	for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, bgp))
		total_established += bgp->established_peers;

	if (uj) {
		json_object_boolean_add(json, "bgpInMaintenanceMode",
					(CHECK_FLAG(bm->flags, BM_FLAG_MAINTENANCE_MODE)));
		json_object_int_add(json, "bgpInstanceCount", listcount(bm->bgp));
		json_object_int_add(json, "establishedPeersTotal", total_established);
	} else {
		if (CHECK_FLAG(bm->flags, BM_FLAG_MAINTENANCE_MODE))
			vty_out(vty, "BGP is in Maintenance mode (BGP GSHUT is in effect)\n");

		vty_out(vty, "Number of BGP instances (including default): %d\n",
			listcount(bm->bgp));
		vty_out(vty, "Total established peers: %u\n", total_established);
	}

	if (uj) {
		json_object_boolean_add(json, "bgpWaitForFibSet", bm->wait_for_fib);
	} else {
		vty_out(vty, "BGP suppress FIB pending is %s\n",
			bm->wait_for_fib ? "enabled" : "disabled");
	}

	if (uj) {
		json_object_int_add(json, "bgpInputQueueLimit", bm->inq_limit);
		json_object_int_add(json, "bgpOutputQueueLimit", bm->outq_limit);
		json_object_int_add(json, "zebraAnnounceCount",
				    zebra_announce_count(&bm->zebra_announce_head));
		json_object_int_add(json, "zebraAnnounceEarlyCount",
				    zebra_announce_count(&bm->zebra_announce_early_head));
		json_object_int_add(json, "bgpUpdateDelayTime", bm->v_update_delay);
		json_object_int_add(json, "bgpEstablishWaitTime", bm->v_establish_wait);
		if (bm->v_advertisement_delay != BGP_ADVERTISEMENT_DELAY_DEFAULT)
			json_object_int_add(json, "bgpAdvertisementDelayTime",
					    bm->v_advertisement_delay);
		json_object_int_add(json, "bgpRmapDelayTimer", bm->rmap_update_timer);
		json_object_int_add(json, "bgpRmapDelayTimerRemaining",
				    event_timer_remain_second(bm->t_rmap_update));
		vty_json(vty, json);
	} else {
		vty_out(vty, "BGP Input Queue Limit: %d\n", bm->inq_limit);
		vty_out(vty, "BGP Output Queue Limit: %d\n", bm->outq_limit);
		vty_out(vty, "Zebra announce queue (priority): %zu\n",
			zebra_announce_count(&bm->zebra_announce_early_head));
		vty_out(vty, "Zebra announce queue (normal): %zu\n",
			zebra_announce_count(&bm->zebra_announce_head));

		vty_out(vty, "BGP Global Update Delay Timers:\n");
		vty_out(vty, "  Update Delay Time: %ds\n", bm->v_update_delay);
		vty_out(vty, "  Establish Wait Time: %ds\n", bm->v_establish_wait);
		if (bm->v_advertisement_delay != BGP_ADVERTISEMENT_DELAY_DEFAULT)
			vty_out(vty, "  Advertisement Delay Time: %ds\n",
				bm->v_advertisement_delay);

		vty_out(vty, "BGP route-map Delay Timer: %ds (remaining: %lds)\n",
			bm->rmap_update_timer, event_timer_remain_second(bm->t_rmap_update));
	}
	return CMD_SUCCESS;
}

static void bgp_show_bestpath(struct vty *vty, struct bgp *bgp, json_object *json)
{
	bool use_json = json != NULL;
	const char *link_bw_handling_str;

	switch (bgp->lb_handling) {
	case BGP_LINK_BW_ECMP:
		link_bw_handling_str = "ecmp";
		break;
	case BGP_LINK_BW_IGNORE_BW:
		link_bw_handling_str = "ignore";
		break;
	case BGP_LINK_BW_SKIP_MISSING:
		link_bw_handling_str = "skip-missing";
		break;
	case BGP_LINK_BW_DEFWT_4_MISSING:
		link_bw_handling_str = "default-weight-for-missing";
		break;
	default:
		link_bw_handling_str = "ecmp";
		break;
	}

	if (use_json) {
		json_object *bestpath = json_object_new_object();

		json_object_boolean_add(bestpath, "asPathIgnore",
					CHECK_FLAG(bgp->flags, BGP_FLAG_ASPATH_IGNORE));

		json_object_boolean_add(bestpath, "asPathConfed",
					CHECK_FLAG(bgp->flags, BGP_FLAG_ASPATH_CONFED));

		json_object_boolean_add(bestpath, "asPathMultiPathRelax",
			CHECK_FLAG(bgp->flags, BGP_FLAG_ASPATH_MULTIPATH_RELAX));

		json_object_boolean_add(bestpath, "asPathMultiPathRelaxAsSet",
			CHECK_FLAG(bgp->flags, BGP_FLAG_MULTIPATH_RELAX_AS_SET));

		json_object_boolean_add(bestpath, "peerTypeRelax",
					CHECK_FLAG(bgp->flags, BGP_FLAG_PEERTYPE_MULTIPATH_RELAX));

		json_object_boolean_add(bestpath, "compareRouterId",
					CHECK_FLAG(bgp->flags, BGP_FLAG_COMPARE_ROUTER_ID));

		json_object_boolean_add(bestpath, "medConfed",
					CHECK_FLAG(bgp->flags, BGP_FLAG_MED_CONFED));

		json_object_boolean_add(bestpath, "medMissingAsWorst",
					CHECK_FLAG(bgp->flags, BGP_FLAG_MED_MISSING_AS_WORST));

		json_object_string_add(bestpath, "linkBwHandling", link_bw_handling_str);

		json_object_boolean_add(bestpath, "alwaysCompareMed",
					CHECK_FLAG(bgp->flags, BGP_FLAG_ALWAYS_COMPARE_MED));

		json_object_boolean_add(bestpath, "deterministicMed",
					CHECK_FLAG(bgp->flags, BGP_FLAG_DETERMINISTIC_MED));

		json_object_object_add(json, "bestPath", bestpath);
	} else {
		vty_out(vty, "Best Path Selection Criteria:\n");
		vty_out(vty, "  Ignore AS path is %s\n",
			CHECK_FLAG(bgp->flags, BGP_FLAG_ASPATH_IGNORE) ? "Enabled" : "Disabled");
		vty_out(vty, "  Include confederation ASNs in AS path is %s\n",
			CHECK_FLAG(bgp->flags, BGP_FLAG_ASPATH_CONFED) ? "Enabled" : "Disabled");

		vty_out(vty, "  AS path multi-path-relax is %s",
			CHECK_FLAG(bgp->flags, BGP_FLAG_ASPATH_MULTIPATH_RELAX) ? "Enabled"
										: "Disabled");
		if (CHECK_FLAG(bgp->flags, BGP_FLAG_ASPATH_MULTIPATH_RELAX)) {
			if (CHECK_FLAG(bgp->flags, BGP_FLAG_MULTIPATH_RELAX_AS_SET))
				vty_out(vty, " (aggregate ASes as AS-SET)");
		}
		vty_out(vty, "\n");

		vty_out(vty, "  Peer type relax is %s\n",
			CHECK_FLAG(bgp->flags, BGP_FLAG_PEERTYPE_MULTIPATH_RELAX) ? "Enabled"
										  : "Disabled");

		vty_out(vty, "  Compare router ID is %s\n",
			CHECK_FLAG(bgp->flags, BGP_FLAG_COMPARE_ROUTER_ID) ? "Enabled"
									   : "Disabled");

		vty_out(vty, "  BGP bestpath MED confed is %s\n",
			CHECK_FLAG(bgp->flags, BGP_FLAG_MED_CONFED) ? "Enabled" : "Disabled");

		vty_out(vty, "  BGP bestpath MED missing-as-worst is %s\n",
			CHECK_FLAG(bgp->flags, BGP_FLAG_MED_MISSING_AS_WORST) ? "Enabled"
									      : "Disabled");

		vty_out(vty, "  Link Bandwidth handling set to: %s\n", link_bw_handling_str);

		vty_out(vty, "  Always compare MED is %s\n",
			CHECK_FLAG(bgp->flags, BGP_FLAG_ALWAYS_COMPARE_MED) ? "Enabled"
									    : "Disabled");
		vty_out(vty, "  Deterministic MED is %s\n",
			CHECK_FLAG(bgp->flags, BGP_FLAG_DETERMINISTIC_MED) ? "Enabled"
									   : "Disabled");
	}
}

DEFPY(show_bgp_vrf_bestpath, show_bgp_vrf_bestpath_cmd,
      "show bgp [<view|vrf> VIEWVRFNAME$vrf_name] bestpath [json]",
      SHOW_STR
      BGP_STR
      BGP_INSTANCE_HELP_STR
      "Display the best path selection criteria\n"
      JSON_STR)
{
	struct bgp *bgp = NULL;
	struct listnode *node = NULL;
	struct list *inst = bm->bgp;
	json_object *json = NULL;
	json_object *json_instance = NULL;
	bool uj = use_json(argc, argv);
	const char *name = vrf_name;
	bool show_all_vrfs = false;
	bool show_all_views = false;
	int idx_vrf_view = 0;
	const char *inst_name;
	const char *type_str;

	if (uj)
		json = json_object_new_object();

	/* Determine if 'vrf all' or 'view all' was specified */
	if (name && strmatch(name, "all")) {
		if (argv_find(argv, argc, "vrf", &idx_vrf_view))
			show_all_vrfs = true;
		else if (argv_find(argv, argc, "view", &idx_vrf_view))
			show_all_views = true;
	}

	/* Handle specific VRF/VIEW case */
	if (name && !show_all_vrfs && !show_all_views) {
		bgp = strmatch(name, VRF_DEFAULT_NAME)
			      ? bgp_get_default()
			      : bgp_lookup_by_name(name);

		if (!bgp) {
			if (uj)
				vty_json(vty, json);
			else
				vty_out(vty, "%% Specified BGP instance not found\n");
			return CMD_WARNING;
		}

		/* Output single VRF/VIEW info */
		if (uj) {
			json_instance = json_object_new_object();
			bgp_show_bestpath(vty, bgp, json_instance);
			json_object_object_add(json, name, json_instance);
			vty_json(vty, json);
		} else {
			type_str = (bgp->inst_type == BGP_INSTANCE_TYPE_VIEW) ? "View" : "VRF";
			vty_out(vty, "%s %s\n", type_str, name);
			bgp_show_bestpath(vty, bgp, NULL);
		}
		return CMD_SUCCESS;
	}

	/* Handle all VRFs and/or VIEWs case */
	for (ALL_LIST_ELEMENTS_RO(inst, node, bgp)) {

		switch (bgp->inst_type) {
		case BGP_INSTANCE_TYPE_DEFAULT:
			inst_name = VRF_DEFAULT_NAME;
			type_str = "VRF";
			/* Skip if showing views only */
			if (show_all_views)
				continue;
			break;
		case BGP_INSTANCE_TYPE_VRF:
			inst_name = bgp->name;
			type_str = "VRF";
			/* Skip if showing views only */
			if (show_all_views)
				continue;
			break;
		case BGP_INSTANCE_TYPE_VIEW:
			inst_name = bgp->name;
			type_str = "View";
			/* Skip if showing vrfs only */
			if (show_all_vrfs)
				continue;
			break;
		default:
			continue;
		}

		if (uj) {
			json_instance = json_object_new_object();
			bgp_show_bestpath(vty, bgp, json_instance);
			json_object_object_add(json, inst_name, json_instance);
		} else {
			vty_out(vty, "%s %s\n", type_str, inst_name);
			bgp_show_bestpath(vty, bgp, NULL);
		}
	}

	if (uj)
		vty_json(vty, json);

	return CMD_SUCCESS;
}

DEFUN (show_bgp_mac_hash,
       show_bgp_mac_hash_cmd,
       "show bgp mac hash",
       SHOW_STR
       BGP_STR
       "Mac Address\n"
       "Mac Address database\n")
{
	bgp_mac_dump_table(vty);

	return CMD_SUCCESS;
}

static void show_tip_entry(struct hash_bucket *bucket, void *args)
{
	struct vty *vty = (struct vty *)args;
	struct tip_addr *tip = (struct tip_addr *)bucket->data;

	vty_out(vty, "addr: %pIA, count: %d\n", &tip->addr, tip->refcnt);
}

static void bgp_show_martian_nexthops(struct vty *vty, struct bgp *bgp)
{
	vty_out(vty, "self nexthop database:\n");
	bgp_nexthop_show_address_hash(vty, bgp);

	vty_out(vty, "Tunnel-ip database:\n");
	hash_iterate(bgp->tip_hash,
		     (void (*)(struct hash_bucket *, void *))show_tip_entry,
		     vty);
}

DEFUN(show_bgp_martian_nexthop_db, show_bgp_martian_nexthop_db_cmd,
      "show bgp [<view|vrf> VIEWVRFNAME] martian next-hop",
      SHOW_STR BGP_STR BGP_INSTANCE_HELP_STR
      "martian next-hops\n"
      "martian next-hop database\n")
{
	struct bgp *bgp = NULL;
	int idx = 0;
	char *name = NULL;

	/* [<vrf> VIEWVRFNAME] */
	if (argv_find(argv, argc, "vrf", &idx)) {
		name = argv[idx + 1]->arg;
		if (name && strmatch(name, VRF_DEFAULT_NAME))
			name = NULL;
	} else if (argv_find(argv, argc, "view", &idx))
		/* [<view> VIEWVRFNAME] */
		name = argv[idx + 1]->arg;
	if (name)
		bgp = bgp_lookup_by_name(name);
	else
		bgp = bgp_get_default();

	if (!bgp || IS_BGP_INSTANCE_HIDDEN(bgp)) {
		vty_out(vty, "%% No BGP process is configured\n");
		return CMD_WARNING;
	}
	bgp_show_martian_nexthops(vty, bgp);

	return CMD_SUCCESS;
}

DEFPY(show_bgp_redistribute,
      show_bgp_redistribute_cmd,
      "show bgp <view|vrf> VIEWVRFNAME <ipv4|ipv6> unicast redistribute [json]",
      SHOW_STR
      BGP_STR
      BGP_INSTANCE_HELP_STR
      BGP_AF_STR
      BGP_AF_STR
      BGP_AF_MODIFIER_STR
      "Detailed information on redistribute\n"
      JSON_STR)
{
	afi_t afi = AFI_IP6;
	safi_t safi = SAFI_UNICAST;
	struct bgp *bgp = NULL;
	bool uj = use_json(argc, argv);
	int idx = 0, i = 0;
	json_object *json_redistribute = NULL;
	json_object *json_re = NULL;
	json_object *json = NULL;

	if (uj)
		argc--;

	bgp_vty_find_and_parse_afi_safi_bgp(vty, argv, argc, &idx, &afi, &safi, &bgp, uj);

	if (!idx)
		return CMD_WARNING;

	if (!bgp)
		return CMD_WARNING;

	if (!(afi == AFI_IP || afi == AFI_IP6)) {
		if (uj)
			vty_json_empty(vty, NULL);
		else
			vty_out(vty, "%% Only ipv4 or ipv6 address families are supported\n");
		return CMD_WARNING;
	}

	if (safi != SAFI_UNICAST) {
		if (uj)
			vty_json_empty(vty, NULL);
		else
			vty_out(vty, "%% Only ipv4 unicast or ipv6 unicast are supported\n");
		return CMD_WARNING;
	}

	if (uj) {
		json = json_object_new_object();
		json_re = json_object_new_object();
	}

	for (i = 0; i < ZEBRA_ROUTE_MAX; i++) {
		struct list *red_list;
		struct listnode *node;
		struct bgp_redist *red;
		json_object *json_route_array = NULL;

		/* Redistribute BGP does not make sense.  */
		if (i == ZEBRA_ROUTE_BGP)
			continue;

		red_list = bgp->redist[afi][i];
		if (!red_list)
			continue;

		if (uj)
			json_route_array = json_object_new_array();

		for (ALL_LIST_ELEMENTS_RO(red_list, node, red)) {
			if (uj) {
				json_redistribute = json_object_new_object();
				if (red->instance)
					json_object_int_add(json_redistribute, "instance",
							    red->instance);
				if (red->redist_metric_flag)
					json_object_int_add(json_redistribute, "metric",
							    red->redist_metric);
				if (red->rmap.name)
					json_object_string_add(json_redistribute, "routeMap",
							       red->rmap.name);

				json_object_array_add(json_route_array, json_redistribute);
			} else {
				vty_out(vty, "  redistribute %s", zebra_route_string(i));
				if (red->instance)
					vty_out(vty, " %d", red->instance);
				if (red->redist_metric_flag)
					vty_out(vty, " metric %u", red->redist_metric);
				if (red->rmap.name)
					vty_out(vty, " route-map %s", red->rmap.name);
				vty_out(vty, "\n");
			}
		}

		if (uj && json_route_array)
			json_object_object_add(json_re, zebra_route_string(i), json_route_array);
	}

	if (uj) {
		json_object_object_add(json, "redistribute", json_re);
		vty_json(vty, json);
	}

	return CMD_SUCCESS;
}

static void bgp_show_aggregate_one(struct vty *vty, const struct prefix *p,
				   struct bgp_aggregate *aggregate, json_object *json_aggregates)
{
	json_object *json_aggr = NULL;

	if (json_aggregates)
		json_aggr = json_object_new_object();

	if (json_aggr) {
		json_object_boolean_add(json_aggr, "summaryOnly", aggregate->summary_only);
		json_object_boolean_add(json_aggr, "asSet", aggregate->as_set);
		json_object_string_add(json_aggr, "origin",
				       aggregate->origin == BGP_ORIGIN_IGP   ? "igp"
				       : aggregate->origin == BGP_ORIGIN_EGP ? "egp"
									     : "incomplete");
		json_object_int_add(json_aggr, "matchingRouteCount", aggregate->count);
		json_object_int_add(json_aggr, "incompleteOriginCount",
				    aggregate->incomplete_origin_count);
		json_object_int_add(json_aggr, "egpOriginCount", aggregate->egp_origin_count);
		json_object_boolean_add(json_aggr, "matchMed", aggregate->match_med);
		json_object_boolean_add(json_aggr, "medInitialized", aggregate->med_initialized);
		json_object_boolean_add(json_aggr, "medMismatched", aggregate->med_mismatched);
		if (aggregate->med_initialized)
			json_object_int_add(json_aggr, "medValue", aggregate->med_matched_value);
		if (aggregate->rmap.name)
			json_object_string_add(json_aggr, "routeMap", aggregate->rmap.name);
		if (aggregate->suppress_map_name)
			json_object_string_add(json_aggr, "suppressMap",
					       aggregate->suppress_map_name);
		if (aggregate->community)
			json_object_string_add(json_aggr, "community",
					       community_str(aggregate->community, false));
		if (aggregate->ecommunity)
			json_object_string_add(json_aggr, "extendedCommunity",
					       ecommunity_str(aggregate->ecommunity));
		if (aggregate->lcommunity)
			json_object_string_add(json_aggr, "largeCommunity",
					       lcommunity_str(aggregate->lcommunity, false));
		if (aggregate->aspath)
			json_object_string_add(json_aggr, "asPath",
					       aspath_print(aggregate->aspath));

		json_object_object_addf(json_aggregates, json_aggr, "%pFX", p);
	} else {
		vty_out(vty, "\nAggregate: %pFX\n", p);
		vty_out(vty, "  Summary-only: %s, AS-set: %s\n",
			aggregate->summary_only ? "yes" : "no", aggregate->as_set ? "yes" : "no");
		vty_out(vty, "  Origin: %s\n",
			aggregate->origin == BGP_ORIGIN_IGP   ? "igp"
			: aggregate->origin == BGP_ORIGIN_EGP ? "egp"
							      : "incomplete");
		vty_out(vty, "  Matching routes: %lu (incomplete: %lu, egp: %lu)\n",
			aggregate->count, aggregate->incomplete_origin_count,
			aggregate->egp_origin_count);
		vty_out(vty, "  MED: match=%s, initialized=%s, mismatched=%s",
			aggregate->match_med ? "yes" : "no",
			aggregate->med_initialized ? "yes" : "no",
			aggregate->med_mismatched ? "yes" : "no");
		if (aggregate->med_initialized)
			vty_out(vty, ", value=%u", aggregate->med_matched_value);
		vty_out(vty, "\n");
		if (aggregate->rmap.name)
			vty_out(vty, "  Route-map: %s\n", aggregate->rmap.name);
		if (aggregate->suppress_map_name)
			vty_out(vty, "  Suppress-map: %s\n", aggregate->suppress_map_name);
		if (aggregate->community)
			vty_out(vty, "  Community: %s\n",
				community_str(aggregate->community, false));
		if (aggregate->ecommunity)
			vty_out(vty, "  Extended community: %s\n",
				ecommunity_str(aggregate->ecommunity));
		if (aggregate->lcommunity)
			vty_out(vty, "  Large community: %s\n",
				lcommunity_str(aggregate->lcommunity, false));
		if (aggregate->aspath)
			vty_out(vty, "  AS path: %s\n", aspath_print(aggregate->aspath));
	}
}

DEFPY(show_bgp_aggregate,
      show_bgp_aggregate_cmd,
      "show bgp [<view|vrf> VIEWVRFNAME$vrf_name] <ipv4|ipv6>$afi_str unicast aggregate-address [<A.B.C.D/M|X:X::X:X/M>$prefix] [json$uj]",
      SHOW_STR
      BGP_STR
      BGP_INSTANCE_HELP_STR
      BGP_AF_STR
      BGP_AF_STR
      BGP_AF_MODIFIER_STR
      "Display aggregate-address runtime information\n"
      "IPv4 prefix\n"
      "IPv6 prefix\n"
      JSON_STR)
{
	afi_t afi;
	struct bgp *bgp = NULL;
	struct bgp_dest *dest;
	struct bgp_aggregate *aggregate;
	const struct prefix *p;
	bool found = false;
	json_object *json = NULL;
	json_object *json_aggregates = NULL;

	if (strmatch(afi_str, "ipv4"))
		afi = AFI_IP;
	else
		afi = AFI_IP6;

	if (vrf_name) {
		bgp = bgp_lookup_by_name(vrf_name);
		if (!bgp) {
			if (uj)
				vty_json_empty(vty, NULL);
			else
				vty_out(vty, "%% BGP instance not found: %s\n", vrf_name);
			return CMD_WARNING;
		}
	} else {
		bgp = bgp_get_default();
		if (!bgp) {
			if (uj)
				vty_json_empty(vty, NULL);
			else
				vty_out(vty, "%% No default BGP instance\n");
			return CMD_WARNING;
		}
	}

	if (prefix_str) {
		if ((afi == AFI_IP && prefix->family != AF_INET) ||
		    (afi == AFI_IP6 && prefix->family != AF_INET6)) {
			if (uj)
				vty_json_empty(vty, NULL);
			else
				vty_out(vty, "%% Prefix family doesn't match address-family\n");
			return CMD_WARNING;
		}
	}

	if (!bgp->aggregate[afi][SAFI_UNICAST]) {
		if (uj)
			vty_json_empty(vty, NULL);
		else
			vty_out(vty, "%% No aggregates configured\n");
		return CMD_SUCCESS;
	}

	if (uj) {
		json = json_object_new_object();
		json_aggregates = json_object_new_object();
	}

	if (prefix_str) {
		/* Exact match lookup for specific prefix */
		dest = bgp_node_lookup(bgp->aggregate[afi][SAFI_UNICAST], prefix);
		if (dest) {
			aggregate = bgp_dest_get_bgp_aggregate_info(dest);
			if (aggregate) {
				found = true;
				bgp_show_aggregate_one(vty, prefix, aggregate, json_aggregates);
			}
			bgp_dest_unlock_node(dest);
		}
	} else {
		/* Iterate through all aggregates */
		for (dest = bgp_table_top(bgp->aggregate[afi][SAFI_UNICAST]); dest;
		     dest = bgp_route_next(dest)) {
			aggregate = bgp_dest_get_bgp_aggregate_info(dest);
			if (!aggregate)
				continue;

			p = bgp_dest_get_prefix(dest);
			found = true;
			bgp_show_aggregate_one(vty, p, aggregate, json_aggregates);
		}
	}

	if (uj) {
		json_object_object_add(json, "aggregates", json_aggregates);
		vty_json(vty, json);
	} else if (!found) {
		if (prefix_str)
			vty_out(vty, "%% Aggregate %pFX not found\n", prefix);
		else
			vty_out(vty, "%% No aggregates found\n");
	}

	return CMD_SUCCESS;
}

DEFUN (show_bgp_memory,
       show_bgp_memory_cmd,
       "show [ip] bgp memory",
       SHOW_STR
       IP_STR
       BGP_STR
       "Global BGP memory statistics\n")
{
	char memstrbuf[MTYPE_MEMSTR_LEN];
	unsigned long count;

	/* RIB related usage stats */
	count = mtype_stats_alloc(MTYPE_BGP_NODE);
	vty_out(vty, "%ld RIB nodes, using %s of memory\n", count,
		mtype_memstr(memstrbuf, sizeof(memstrbuf),
			     count * sizeof(struct bgp_dest)));

	count = mtype_stats_alloc(MTYPE_BGP_ROUTE);
	vty_out(vty, "%ld BGP routes, using %s of memory\n", count,
		mtype_memstr(memstrbuf, sizeof(memstrbuf),
			     count * sizeof(struct bgp_path_info)));
	if ((count = mtype_stats_alloc(MTYPE_BGP_ROUTE_EXTRA)))
		vty_out(vty, "%ld BGP route ancillaries, using %s of memory\n",
			count,
			mtype_memstr(
				memstrbuf, sizeof(memstrbuf),
				count * sizeof(struct bgp_path_info_extra)));

	count = mtype_stats_alloc(MTYPE_BGP_ROUTE_EXTRA_EVPN);
	if (count)
		vty_out(vty, "%ld BGP extra info for EVPN, using %s of memory\n",
			count,
			mtype_memstr(memstrbuf, sizeof(memstrbuf),
				     count * sizeof(struct bgp_path_info_extra_evpn)));

	count = mtype_stats_alloc(MTYPE_BGP_ROUTE_EXTRA_FS);
	if (count)
		vty_out(vty,
			"%ld BGP extra info for flowspec, using %s of memory\n",
			count,
			mtype_memstr(memstrbuf, sizeof(memstrbuf),
				     count * sizeof(struct bgp_path_info_extra_fs)));

	count = mtype_stats_alloc(MTYPE_BGP_ROUTE_EXTRA_VRFLEAK);
	if (count)
		vty_out(vty,
			"%ld BGP extra info for vrf leaking, using %s of memory\n",
			count,
			mtype_memstr(memstrbuf, sizeof(memstrbuf),
				     count * sizeof(struct bgp_path_info_extra_vrfleak)));

	if ((count = mtype_stats_alloc(MTYPE_BGP_STATIC)))
		vty_out(vty, "%ld Static routes, using %s of memory\n", count,
			mtype_memstr(memstrbuf, sizeof(memstrbuf),
				     count * sizeof(struct bgp_static)));

	if ((count = mtype_stats_alloc(MTYPE_BGP_PACKET)))
		vty_out(vty, "%ld Packets, using %s of memory\n", count,
			mtype_memstr(memstrbuf, sizeof(memstrbuf),
				     count * sizeof(struct bpacket)));

	/* Adj-In/Out */
	if ((count = mtype_stats_alloc(MTYPE_BGP_ADJ_IN)))
		vty_out(vty, "%ld Adj-In entries, using %s of memory\n", count,
			mtype_memstr(memstrbuf, sizeof(memstrbuf),
				     count * sizeof(struct bgp_adj_in)));
	if ((count = mtype_stats_alloc(MTYPE_BGP_ADJ_OUT)))
		vty_out(vty, "%ld Adj-Out entries, using %s of memory\n", count,
			mtype_memstr(memstrbuf, sizeof(memstrbuf),
				     count * sizeof(struct bgp_adj_out)));

	if ((count = mtype_stats_alloc(MTYPE_BGP_NEXTHOP_CACHE)))
		vty_out(vty, "%ld Nexthop cache entries, using %s of memory\n",
			count,
			mtype_memstr(memstrbuf, sizeof(memstrbuf),
				     count * sizeof(struct bgp_nexthop_cache)));

	if ((count = mtype_stats_alloc(MTYPE_BGP_DAMP_INFO)))
		vty_out(vty, "%ld Dampening entries, using %s of memory\n",
			count,
			mtype_memstr(memstrbuf, sizeof(memstrbuf),
				     count * sizeof(struct bgp_damp_info)));

	/* Attributes */
	count = attr_count();
	vty_out(vty, "%ld BGP attributes, using %s of memory\n", count,
		mtype_memstr(memstrbuf, sizeof(memstrbuf),
			     count * sizeof(struct attr)));

	if ((count = attr_unknown_count()))
		vty_out(vty, "%ld unknown attributes\n", count);

	/* AS_PATH attributes */
	count = aspath_count();
	vty_out(vty, "%ld BGP AS-PATH entries, using %s of memory\n", count,
		mtype_memstr(memstrbuf, sizeof(memstrbuf),
			     count * sizeof(struct aspath)));

	count = mtype_stats_alloc(MTYPE_AS_SEG);
	vty_out(vty, "%ld BGP AS-PATH segments, using %s of memory\n", count,
		mtype_memstr(memstrbuf, sizeof(memstrbuf),
			     count * sizeof(struct assegment)));

	/* Other attributes */
	if ((count = community_count()))
		vty_out(vty, "%ld BGP community entries, using %s of memory\n",
			count, mtype_memstr(memstrbuf, sizeof(memstrbuf),
					    count * sizeof(struct community)));
	if ((count = mtype_stats_alloc(MTYPE_ECOMMUNITY)))
		vty_out(vty,
			"%ld BGP ext-community entries, using %s of memory\n",
			count,
			mtype_memstr(memstrbuf, sizeof(memstrbuf),
				     count * sizeof(struct ecommunity)));
	if ((count = mtype_stats_alloc(MTYPE_LCOMMUNITY)))
		vty_out(vty,
			"%ld BGP large-community entries, using %s of memory\n",
			count, mtype_memstr(memstrbuf, sizeof(memstrbuf),
					    count * sizeof(struct lcommunity)));

	if ((count = mtype_stats_alloc(MTYPE_CLUSTER)))
		vty_out(vty, "%ld Cluster lists, using %s of memory\n", count,
			mtype_memstr(memstrbuf, sizeof(memstrbuf),
				     count * sizeof(struct cluster_list)));

	/* Peer related usage */
	count = mtype_stats_alloc(MTYPE_BGP_PEER);
	vty_out(vty, "%ld peers, using %s of memory\n", count,
		mtype_memstr(memstrbuf, sizeof(memstrbuf),
			     count * sizeof(struct peer)));

	if ((count = mtype_stats_alloc(MTYPE_PEER_GROUP)))
		vty_out(vty, "%ld peer groups, using %s of memory\n", count,
			mtype_memstr(memstrbuf, sizeof(memstrbuf),
				     count * sizeof(struct peer_group)));

	/* Other */
	if ((count = mtype_stats_alloc(MTYPE_BGP_REGEXP)))
		vty_out(vty, "%ld compiled regexes, using %s of memory\n", count,
			mtype_memstr(memstrbuf, sizeof(memstrbuf), count * sizeof(struct frregex)));
	return CMD_SUCCESS;
}

static void bgp_show_bestpath_json(struct bgp *bgp, json_object *json)
{
	json_object *bestpath = json_object_new_object();

	if (CHECK_FLAG(bgp->flags, BGP_FLAG_ASPATH_IGNORE))
		json_object_string_add(bestpath, "asPath", "ignore");

	if (CHECK_FLAG(bgp->flags, BGP_FLAG_ASPATH_CONFED))
		json_object_string_add(bestpath, "asPath", "confed");

	if (CHECK_FLAG(bgp->flags, BGP_FLAG_ASPATH_MULTIPATH_RELAX)) {
		if (CHECK_FLAG(bgp->flags, BGP_FLAG_MULTIPATH_RELAX_AS_SET))
			json_object_string_add(bestpath, "multiPathRelax",
					       "as-set");
		else
			json_object_string_add(bestpath, "multiPathRelax",
					       "true");
	} else
		json_object_string_add(bestpath, "multiPathRelax", "false");

	if (CHECK_FLAG(bgp->flags, BGP_FLAG_PEERTYPE_MULTIPATH_RELAX))
		json_object_boolean_true_add(bestpath, "peerTypeRelax");

	if (CHECK_FLAG(bgp->flags, BGP_FLAG_COMPARE_ROUTER_ID))
		json_object_string_add(bestpath, "compareRouterId", "true");
	if (CHECK_FLAG(bgp->flags, BGP_FLAG_MED_CONFED)
	    || CHECK_FLAG(bgp->flags, BGP_FLAG_MED_MISSING_AS_WORST)) {
		if (CHECK_FLAG(bgp->flags, BGP_FLAG_MED_CONFED))
			json_object_string_add(bestpath, "med", "confed");
		if (CHECK_FLAG(bgp->flags, BGP_FLAG_MED_MISSING_AS_WORST))
			json_object_string_add(bestpath, "med",
					       "missing-as-worst");
		else
			json_object_string_add(bestpath, "med", "true");
	}

	json_object_object_add(json, "bestPath", bestpath);
}

/* Print the error code/subcode for why the peer is down */
static void bgp_show_peer_reset(struct vty * vty, struct peer *peer,
				json_object *json_peer, bool use_json)
{
	const char *code_str;
	const char *subcode_str;

	if (use_json) {
		if (peer->last_reset == PEER_DOWN_NOTIFY_SEND
		    || peer->last_reset == PEER_DOWN_NOTIFY_RECEIVED) {
			char errorcodesubcode_hexstr[5];
			char errorcodesubcode_str[256];

			code_str = bgp_notify_code_str(peer->notify.code);
			subcode_str = bgp_notify_subcode_str(
					 peer->notify.code,
					 peer->notify.subcode);

			snprintf(errorcodesubcode_hexstr,
				 sizeof(errorcodesubcode_hexstr), "%02X%02X",
				 peer->notify.code, peer->notify.subcode);
			json_object_string_add(json_peer,
					       "lastErrorCodeSubcode",
					       errorcodesubcode_hexstr);
			snprintf(errorcodesubcode_str, 255, "%s%s",
				 code_str, subcode_str);
			json_object_string_add(json_peer,
					       "lastNotificationReason",
					       errorcodesubcode_str);
			json_object_boolean_add(json_peer,
						"lastNotificationHardReset",
						peer->notify.hard_reset);
			if (peer->last_reset == PEER_DOWN_NOTIFY_RECEIVED
			    && peer->notify.code == BGP_NOTIFY_CEASE
			    && (peer->notify.subcode
				== BGP_NOTIFY_CEASE_ADMIN_SHUTDOWN
				|| peer->notify.subcode
				== BGP_NOTIFY_CEASE_ADMIN_RESET)
			    && peer->notify.length) {
				char msgbuf[1024];
				const char *msg_str;

				msg_str = bgp_notify_admin_message(
					     msgbuf, sizeof(msgbuf),
					     (uint8_t *)peer->notify.data,
					     peer->notify.length);
				json_object_string_add(json_peer,
				   "lastShutdownDescription",
				   msg_str);
			}

		}
		json_object_string_add(json_peer, "lastResetDueTo",
				       peer_down_str[(int)peer->last_reset]);
		json_object_int_add(json_peer, "lastResetCode",
				    peer->last_reset);
		if (peer->down_last_reset != PEER_DOWN_NONE) {
			json_object_string_add(json_peer, "downLastResetDueTo",
					       peer_down_str[peer->down_last_reset]);
			json_object_int_add(json_peer, "downLastResetCode", peer->down_last_reset);
			json_object_int_add(json_peer, "downLastResetTimeSecs",
					    monotime(NULL) - peer->down_resettime);
		}
		json_object_string_add(json_peer, "softwareVersion",
				       peer->soft_version ? peer->soft_version
							  : "n/a");
	} else {
		if (peer->last_reset == PEER_DOWN_NOTIFY_SEND
		    || peer->last_reset == PEER_DOWN_NOTIFY_RECEIVED) {
			code_str = bgp_notify_code_str(peer->notify.code);
			subcode_str =
				bgp_notify_subcode_str(peer->notify.code,
						       peer->notify.subcode);
			vty_out(vty, " Notification %s (%s%s%s)\n",
				peer->last_reset == PEER_DOWN_NOTIFY_SEND
					? "sent"
					: "received",
				code_str, subcode_str,
				peer->notify.hard_reset
					? bgp_notify_subcode_str(
						  BGP_NOTIFY_CEASE,
						  BGP_NOTIFY_CEASE_HARD_RESET)
					: "");
		} else {
			vty_out(vty, " %s (%s)\n",
				peer_down_str[(int)peer->last_reset],
				peer->soft_version ? peer->soft_version : "n/a");
			if (peer->down_last_reset != PEER_DOWN_NONE)
				vty_out(vty, "  Down last reset: %s, %u seconds ago\n",
					peer_down_str[peer->down_last_reset],
					(unsigned int)(monotime(NULL) - peer->down_resettime));
		}
	}
}

static inline bool bgp_has_peer_failed(struct peer *peer, afi_t afi,
				       safi_t safi)
{
	return ((!peer_established(peer->connection)) ||
		!peer->afc_recv[afi][safi]);
}

static void bgp_show_failed_summary(struct vty *vty, struct bgp *bgp,
				    struct peer *peer, json_object *json_peer,
				    int max_neighbor_width, bool use_json)
{
	char timebuf[BGP_UPTIME_LEN], dn_flag[2];
	int len;

	if (use_json) {
		if (peer_dynamic_neighbor(peer))
			json_object_boolean_true_add(json_peer,
						     "dynamicPeer");
		if (peer->hostname)
			json_object_string_add(json_peer, "hostname",
					       peer->hostname);

		if (peer->domainname)
			json_object_string_add(json_peer, "domainname",
					       peer->domainname);
		json_object_int_add(json_peer, "connectionsEstablished",
				    peer->established);
		json_object_int_add(json_peer, "connectionsDropped",
				    peer->dropped);
		peer_uptime(peer->uptime, timebuf, BGP_UPTIME_LEN,
			    use_json, json_peer);
		bgp_show_peer_reset(NULL, peer, json_peer, true);
	} else {
		dn_flag[1] = '\0';
		dn_flag[0] = peer_dynamic_neighbor(peer) ? '*' : '\0';
		if (peer->hostname
		    && CHECK_FLAG(bgp->flags, BGP_FLAG_SHOW_HOSTNAME))
			len = vty_out(vty, "%s%s(%s)", dn_flag,
				      peer->hostname, peer->host);
		else
			len = vty_out(vty, "%s%s", dn_flag, peer->host);

		/* pad the neighbor column with spaces */
		if (len < max_neighbor_width)
			vty_out(vty, "%*s", max_neighbor_width - len,
				" ");
		vty_out(vty, "%7d %7d %9s", peer->established,
			peer->dropped,
			peer_uptime(peer->uptime, timebuf,
				    BGP_UPTIME_LEN, 0, NULL));
		bgp_show_peer_reset(vty, peer, NULL, false);
	}
}

/* Strip peer's description to the given size. */
static char *bgp_peer_description_stripped(char *desc, uint32_t size)
{
	static char stripped[BUFSIZ];
	uint32_t i = 0;
	uint32_t last_space = size;

	while (i < size) {
		if (*(desc + i) == '\0') {
			stripped[i] = '\0';
			return stripped;
		}
		if (i != 0 && *(desc + i) == ' ' && last_space != i - 1)
			last_space = i;
		stripped[i] = *(desc + i);
		i++;
	}

	stripped[last_space] = '\0';

	return stripped;
}

/* Determine whether var peer should be filtered out of the summary. */
static bool bgp_show_summary_is_peer_filtered(struct peer *peer,
					      struct peer *fpeer,
					      enum peer_asn_type as_type,
					      as_t as)
{

	/* filter neighbor XXXX */
	if (fpeer && fpeer != peer)
		return true;

	/* filter remote-as (internal|external) */
	if (as_type != AS_UNSPECIFIED) {
		if (peer->as_type == AS_SPECIFIED) {
			if (CHECK_FLAG(as_type, AS_INTERNAL)) {
				if (peer->as != peer->local_as)
					return true;
			} else if (peer->as == peer->local_as)
				return true;
		} else if (as_type != peer->as_type)
			return true;
	} else if (as && as != peer->as) /* filter remote-as XXX */
		return true;

	return false;
}

/* Show BGP peer's summary information.
 *
 * Peer's description is stripped according to if `wide` option is given
 * or not.
 *
 * When adding new columns to `show bgp summary` output, please make
 * sure `Desc` is the latest column to show because it can contain
 * whitespaces and the whole output will be tricky.
 */
static void bgp_show_summary_update_delay(struct vty *vty, struct bgp *bgp,
					  json_object *json, bool use_json)
{
	if (!bgp_update_delay_configured(bgp))
		return;

	if (use_json) {
		json_object_int_add(json, "updateDelayLimit",
				    bgp->v_update_delay);
		if (bgp->v_update_delay != bgp->v_establish_wait)
			json_object_int_add(json, "updateDelayEstablishWait",
					    bgp->v_establish_wait);
		if (bgp_update_delay_active(bgp)) {
			json_object_string_add(json,
					       "updateDelayFirstNeighbor",
					       bgp->update_delay_begin_time);
			json_object_boolean_true_add(json,
						     "updateDelayInProgress");
		} else if (bgp->update_delay_over) {
			json_object_string_add(json,
					       "updateDelayFirstNeighbor",
					       bgp->update_delay_begin_time);
			json_object_string_add(json,
					       "updateDelayBestpathResumed",
					       bgp->update_delay_end_time);
			json_object_string_add(
				json, "updateDelayZebraUpdateResume",
				bgp->update_delay_zebra_resume_time);
			if (bgp->update_delay_peers_resume_time[0] != '\0')
				json_object_string_add(
					json, "updateDelayPeerUpdateResume",
					bgp->update_delay_peers_resume_time);
		}
	} else {
		vty_out(vty,
			"Read-only mode update-delay limit: %d seconds\n",
			bgp->v_update_delay);
		if (bgp->v_update_delay != bgp->v_establish_wait)
			vty_out(vty,
				"                   Establish wait: %d seconds\n",
				bgp->v_establish_wait);
		if (bgp_update_delay_active(bgp)) {
			vty_out(vty,
				"  First neighbor established: %s\n",
				bgp->update_delay_begin_time);
			vty_out(vty, "  Delay in progress\n");
		} else if (bgp->update_delay_over) {
			vty_out(vty,
				"  First neighbor established: %s\n",
				bgp->update_delay_begin_time);
			vty_out(vty,
				"          Best-paths resumed: %s\n",
				bgp->update_delay_end_time);
			vty_out(vty,
				"        zebra update resumed: %s\n",
				bgp->update_delay_zebra_resume_time);
			if (bgp->update_delay_peers_resume_time[0] != '\0')
				vty_out(vty,
					"        peers update resumed: %s\n",
					bgp->update_delay_peers_resume_time);
		}
	}
}

static void bgp_show_summary_advertisement_delay(struct vty *vty,
						  struct bgp *bgp,
						  json_object *json,
						  bool use_json)
{
	if (!bgp_advertisement_delay_configured(bgp))
		return;

	if (use_json) {
		json_object_int_add(json, "advertisementDelay",
				    bgp->v_advertisement_delay);
		if (bgp_advertisement_delay_active(bgp)) {
			json_object_boolean_true_add(
				json, "advertisementDelayInProgress");
			json_object_int_add(
				json, "advertisementDelayRemainingSeconds",
				event_timer_remain_second(
					bgp->t_advertisement_delay));
		} else if (bgp->advertisement_delay_resume_time[0] != '\0')
			json_object_string_add(
				json, "advertisementDelayResumeTime",
				bgp->advertisement_delay_resume_time);
	} else {
		vty_out(vty, "Advertisement delay: %d seconds\n",
			bgp->v_advertisement_delay);
		if (bgp_advertisement_delay_active(bgp))
			vty_out(vty, "  %lu seconds remaining\n",
				event_timer_remain_second(
					bgp->t_advertisement_delay));
		else if (bgp->advertisement_delay_resume_time[0] != '\0')
			vty_out(vty, "  advertisements resumed: %s\n",
				bgp->advertisement_delay_resume_time);
	}
}

/*
 * Per-instance identification header, shared by the peered and the peerless
 * paths of bgp_show_summary().
 */
static void bgp_show_summary_instance_header(struct vty *vty, struct bgp *bgp, json_object *json,
					     bool use_json)
{
	int64_t vrf_id_ui = (bgp->vrf_id == VRF_UNKNOWN) ? -1 : (int64_t)bgp->vrf_id;

	if (use_json) {
		json_object_string_addf(json, "routerId", "%pI4", &bgp->router_id);
		asn_asn2json(json, "as", bgp->as, bgp->asnotation);
		json_object_int_add(json, "vrfId", vrf_id_ui);
		json_object_string_add(json, "vrfName",
				       bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT
					       ? VRF_DEFAULT_NAME
					       : bgp->name);
	} else {
		vty_out(vty, "BGP router identifier %pI4, local AS number %s %s vrf-id %d\n",
			&bgp->router_id, bgp->as_pretty, bgp->name_pretty, (int)vrf_id_ui);
	}
}

static unsigned long bgp_show_summary_rib_count(struct bgp *bgp, afi_t afi, safi_t safi)
{
	struct bgp_table *table = bgp->rib[afi][safi];
	struct bgp_dest *rd_dest;
	unsigned long count = 0;

	if (safi != SAFI_EVPN)
		return bgp_table_count(table);

	/* Global EVPN prefixes are stored in per-RD tables. */
	for (rd_dest = bgp_table_top(table); rd_dest; rd_dest = bgp_route_next(rd_dest)) {
		struct bgp_table *rd_table;

		rd_table = bgp_dest_get_bgp_table_info(rd_dest);
		if (rd_table)
			count += bgp_table_count(rd_table);
	}

	return count;
}

static int bgp_show_summary(struct vty *vty, struct bgp *bgp, int afi, int safi,
			    struct peer *fpeer, enum peer_asn_type as_type,
			    as_t as, uint16_t show_flags)
{
	struct peer *peer;
	struct listnode *node, *nnode;
	unsigned int count = 0, dn_count = 0;
	char timebuf[BGP_UPTIME_LEN], dn_flag[2];
	char neighbor_buf[VTY_BUFSIZ];
	int neighbor_col_default_width = 16;
	int len, failed_count = 0;
	unsigned int filtered_count = 0;
	int max_neighbor_width = 0;
	int pfx_rcd_safi;
	json_object *json = NULL;
	json_object *json_peer = NULL;
	json_object *json_peers = NULL;
	struct peer_af *paf;
	struct bgp_filter *filter;
	bool use_json = CHECK_FLAG(show_flags, BGP_SHOW_OPT_JSON);
	bool show_failed = CHECK_FLAG(show_flags, BGP_SHOW_OPT_FAILED);
	bool show_established =
		CHECK_FLAG(show_flags, BGP_SHOW_OPT_ESTABLISHED);
	bool show_wide = CHECK_FLAG(show_flags, BGP_SHOW_OPT_WIDE);
	bool show_terse = CHECK_FLAG(show_flags, BGP_SHOW_OPT_TERSE);

	/* labeled-unicast routes are installed in the unicast table so in order
	 * to
	 * display the correct PfxRcd value we must look at SAFI_UNICAST
	 */

	if (safi == SAFI_LABELED_UNICAST)
		pfx_rcd_safi = SAFI_UNICAST;
	else
		pfx_rcd_safi = safi;

	if (use_json) {
		json = json_object_new_object();
		json_peers = json_object_new_object();
		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
			if (bgp_show_summary_is_peer_filtered(peer, fpeer,
							      as_type, as)) {
				filtered_count++;
				count++;
				continue;
			}

			if (!peer_is_config_node(peer))
				continue;

			if (peer->afc[afi][safi]) {
				/* See if we have at least a single failed peer */
				if (bgp_has_peer_failed(peer, afi, safi))
					failed_count++;
				count++;
			}
			if (peer_dynamic_neighbor(peer))
				dn_count++;
		}

	} else {
		/* Loop over all neighbors that will be displayed to determine
		 * how many
		 * characters are needed for the Neighbor column
		 */
		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
			if (bgp_show_summary_is_peer_filtered(peer, fpeer,
							      as_type, as)) {
				filtered_count++;
				count++;
				continue;
			}

			if (!peer_is_config_node(peer))
				continue;

			if (peer->afc[afi][safi]) {
				memset(dn_flag, '\0', sizeof(dn_flag));
				if (peer_dynamic_neighbor(peer))
					dn_flag[0] = '*';

				if (peer->hostname
				    && CHECK_FLAG(bgp->flags,
						  BGP_FLAG_SHOW_HOSTNAME))
					snprintf(neighbor_buf,
						 sizeof(neighbor_buf),
						 "%s%s(%s) ", dn_flag,
						 peer->hostname, peer->host);
				else
					snprintf(neighbor_buf,
						 sizeof(neighbor_buf), "%s%s ",
						 dn_flag, peer->host);

				len = strlen(neighbor_buf);

				if (len > max_neighbor_width)
					max_neighbor_width = len;

				/* See if we have at least a single failed peer */
				if (bgp_has_peer_failed(peer, afi, safi))
					failed_count++;
				count++;
			}
		}

		/* Originally we displayed the Neighbor column as 16
		 * characters wide so make that the default
		 */
		if (max_neighbor_width < neighbor_col_default_width)
			max_neighbor_width = neighbor_col_default_width;
	}

	if (show_failed && !failed_count) {
		if (use_json) {
			json_object_free(json_peers);

			json_object_int_add(json, "failedPeersCount", 0);
			json_object_int_add(json, "dynamicPeers", dn_count);
			json_object_int_add(json, "totalPeers", count);

			vty_json(vty, json);
		} else {
			vty_out(vty, "%% No failed BGP neighbors found\n");
		}
		return CMD_SUCCESS;
	}

	count = 0;		/* Reset the value as its used again */
	filtered_count = 0;
	dn_count = 0;
	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
		if (!peer_is_config_node(peer))
			continue;

		if (!peer->afc[afi][safi])
			continue;

		if (!count) {
			unsigned long ents;
			char memstrbuf[MTYPE_MEMSTR_LEN];

			/* Usage summary and header */
			bgp_show_summary_instance_header(vty, bgp, json, use_json);

			bgp_show_summary_update_delay(vty, bgp, json,
						     use_json);

			bgp_show_summary_advertisement_delay(vty, bgp, json, use_json);

			if (use_json) {
				if (bgp_maxmed_onstartup_configured(bgp)
				    && bgp->maxmed_active)
					json_object_boolean_true_add(
						json, "maxMedOnStartup");
				if (bgp->v_maxmed_admin)
					json_object_boolean_true_add(
						json, "maxMedAdministrative");

				json_object_int_add(
					json, "tableVersion",
					bgp_table_version(bgp->rib[afi][safi]));

				ents = bgp_show_summary_rib_count(bgp, afi, safi);
				json_object_int_add(json, "ribCount", ents);
				json_object_int_add(
					json, "ribMemory",
					ents * sizeof(struct bgp_dest));

				ents = bgp->af_peer_count[afi][safi];
				json_object_int_add(json, "peerCount", ents);
				json_object_int_add(json, "peerMemory",
						    ents * sizeof(struct peer));

				if ((ents = listcount(bgp->group))) {
					json_object_int_add(
						json, "peerGroupCount", ents);
					json_object_int_add(
						json, "peerGroupMemory",
						ents * sizeof(struct
							      peer_group));
				}

				if (CHECK_FLAG(bgp->af_flags[afi][safi],
					       BGP_CONFIG_DAMPENING))
					json_object_boolean_true_add(
						json, "dampeningEnabled");
			} else {
				if (!show_terse) {
					if (bgp_maxmed_onstartup_configured(bgp)
					    && bgp->maxmed_active)
						vty_out(vty,
							"Max-med on-startup active\n");
					if (bgp->v_maxmed_admin)
						vty_out(vty,
							"Max-med administrative active\n");

					vty_out(vty,
						"BGP table version %" PRIu64
						"\n",
						bgp_table_version(
							bgp->rib[afi][safi]));

					ents = bgp_show_summary_rib_count(bgp, afi, safi);
					vty_out(vty,
						"RIB entries %ld, using %s of memory\n",
						ents,
						mtype_memstr(
							memstrbuf,
							sizeof(memstrbuf),
							ents
								* sizeof(
									struct
									bgp_dest)));

					/* Peer related usage */
					ents = bgp->af_peer_count[afi][safi];
					vty_out(vty,
						"Peers %ld, using %s of memory\n",
						ents,
						mtype_memstr(
							memstrbuf,
							sizeof(memstrbuf),
							ents
								* sizeof(
									struct
									peer)));

					if ((ents = listcount(bgp->group)))
						vty_out(vty,
							"Peer groups %ld, using %s of memory\n",
							ents,
							mtype_memstr(
								memstrbuf,
								sizeof(memstrbuf),
								ents
									* sizeof(
										struct
										peer_group)));

					if (CHECK_FLAG(bgp->af_flags[afi][safi],
						       BGP_CONFIG_DAMPENING))
						vty_out(vty,
							"Dampening enabled.\n");
				}
				if (show_failed) {
					vty_out(vty, "\n");

					/* Subtract 8 here because 'Neighbor' is
					 * 8 characters */
					vty_out(vty, "Neighbor");
					vty_out(vty, "%*s",
						max_neighbor_width - 8, " ");
					vty_out(vty,
						BGP_SHOW_SUMMARY_HEADER_FAILED);
				}
			}
		}

		paf = peer_af_find(peer, afi, safi);
		filter = &peer->filter[afi][safi];

		count++;
		/* Works for both failed & successful cases */
		if (peer_dynamic_neighbor(peer))
			dn_count++;

		if (use_json) {
			json_peer = NULL;
			if (bgp_show_summary_is_peer_filtered(peer, fpeer,
							      as_type, as)) {
				filtered_count++;
				continue;
			}
			if (show_failed &&
			    bgp_has_peer_failed(peer, afi, safi)) {
				json_peer = json_object_new_object();
				bgp_show_failed_summary(vty, bgp, peer,
							json_peer, 0, use_json);
			} else if (!show_failed) {
				if (show_established
				    && bgp_has_peer_failed(peer, afi, safi)) {
					filtered_count++;
					continue;
				}

				json_peer = json_object_new_object();
				if (peer_dynamic_neighbor(peer)) {
					json_object_boolean_true_add(json_peer,
								     "dynamicPeer");
				}

				if (peer->hostname)
					json_object_string_add(json_peer, "hostname",
							       peer->hostname);

				if (peer->domainname)
					json_object_string_add(json_peer, "domainname",
							       peer->domainname);

				json_object_string_add(json_peer,
						       "softwareVersion",
						       peer->soft_version
							       ? peer->soft_version
							       : "n/a");

				asn_asn2json(json_peer, "remoteAs", peer->as,
					     bgp->asnotation);
				asn_asn2json(json_peer, "localAs",
					     peer->change_local_as
						     ? peer->change_local_as
						     : peer->local_as,
					     bgp->asnotation);
				json_object_int_add(json_peer, "version", 4);
				json_object_int_add(json_peer, "msgRcvd",
						    PEER_TOTAL_RX(peer));
				json_object_int_add(json_peer, "msgSent",
						    PEER_TOTAL_TX(peer));

				atomic_size_t outq_count, inq_count;
				outq_count =
					atomic_load_explicit(&peer->connection
								      ->obuf
								      ->count,
							     memory_order_relaxed);
				inq_count =
					atomic_load_explicit(&peer->connection
								      ->ibuf
								      ->count,
							     memory_order_relaxed);

				json_object_int_add(
					json_peer, "tableVersion",
					(paf && PAF_SUBGRP(paf))
						? paf->subgroup->version
						: 0);
				json_object_int_add(json_peer, "outq",
						    outq_count);
				json_object_int_add(json_peer, "inq",
						    inq_count);
				peer_uptime(peer->uptime, timebuf, BGP_UPTIME_LEN,
					    use_json, json_peer);

				json_object_int_add(json_peer, "pfxRcd",
						    peer->pcount[afi][pfx_rcd_safi]);

				if (paf && PAF_SUBGRP(paf))
					json_object_int_add(
						json_peer, "pfxSnt",
						(PAF_SUBGRP(paf))->scount);
				else
					json_object_int_add(json_peer, "pfxSnt",
							    0);

				/* BGP FSM state */
				if (CHECK_FLAG(peer->flags, PEER_FLAG_SHUTDOWN)
				    || CHECK_FLAG(peer->bgp->flags,
						  BGP_FLAG_SHUTDOWN))
					json_object_string_add(json_peer,
							       "state",
							       "Idle (Admin)");
				else if (peer->afc_recv[afi][safi])
					json_object_string_add(
						json_peer, "state",
						lookup_msg(bgp_status_msg,
							   peer->connection->status,
							   NULL));
				else if (CHECK_FLAG(
						 peer->sflags,
						 PEER_STATUS_PREFIX_OVERFLOW))
					json_object_string_add(json_peer,
							       "state",
							       "Idle (PfxCt)");
				else
					json_object_string_add(
						json_peer, "state",
						lookup_msg(bgp_status_msg,
							   peer->connection->status,
							   NULL));

				/* BGP peer state */
				if (CHECK_FLAG(peer->flags, PEER_FLAG_SHUTDOWN)
				    || CHECK_FLAG(peer->bgp->flags,
						  BGP_FLAG_SHUTDOWN))
					json_object_string_add(json_peer,
							       "peerState",
							       "Admin");
				else if (CHECK_FLAG(
						 peer->sflags,
						 PEER_STATUS_PREFIX_OVERFLOW))
					json_object_string_add(json_peer,
							       "peerState",
							       "PfxCt");
				else if (CHECK_FLAG(peer->flags,
						    PEER_FLAG_PASSIVE))
					json_object_string_add(json_peer,
							       "peerState",
							       "Passive");
				else if (CHECK_FLAG(peer->sflags,
						    PEER_STATUS_NSF_WAIT))
					json_object_string_add(json_peer,
							       "peerState",
							       "NSF passive");
				else if (CHECK_FLAG(
						 peer->bgp->flags,
						 BGP_FLAG_EBGP_REQUIRES_POLICY)
					 && (!bgp_inbound_policy_exists(peer,
									filter)
					     || !bgp_outbound_policy_exists(
						     peer, filter)))
					json_object_string_add(json_peer,
							       "peerState",
							       "Policy");
				else
					json_object_string_add(
						json_peer, "peerState", "OK");

				json_object_int_add(json_peer, "connectionsEstablished",
						    peer->established);
				json_object_int_add(json_peer, "connectionsDropped",
						    peer->dropped);
				if (peer->desc)
					json_object_string_add(
						json_peer, "desc", peer->desc);
			}
			/* Avoid creating empty peer dicts in JSON */
			if (json_peer == NULL)
				continue;

			if (peer->conf_if)
				json_object_string_add(json_peer, "idType",
						       "interface");
			else if (peer->connection->su.sa.sa_family == AF_INET)
				json_object_string_add(json_peer, "idType",
						       "ipv4");
			else if (peer->connection->su.sa.sa_family == AF_INET6) {
				json_object_string_add(json_peer, "idType",
						       "ipv6");
				if (IN6_IS_ADDR_LINKLOCAL(&peer->connection->su.sin6.sin6_addr)) {
					ifindex_t scope_id =
						peer->connection->su.sin6.sin6_scope_id;

					json_object_int_add(json_peer, "scopeId", scope_id);
					json_object_string_add(json_peer, "scopeIfName",
							       ifindex2ifname(scope_id,
									      bgp->vrf_id));
				}
			}
			json_object_object_add(json_peers, peer->host,
					       json_peer);
		} else {
			if (bgp_show_summary_is_peer_filtered(peer, fpeer,
							      as_type, as)) {
				filtered_count++;
				continue;
			}
			if (show_failed &&
			    bgp_has_peer_failed(peer, afi, safi)) {
				bgp_show_failed_summary(vty, bgp, peer, NULL,
							max_neighbor_width,
							use_json);
			} else if (!show_failed) {
				if (show_established
				    && bgp_has_peer_failed(peer, afi, safi)) {
					filtered_count++;
					continue;
				}

				if ((count - filtered_count) == 1) {
					/* display headline before the first
					 * neighbor line */
					vty_out(vty, "\n");

					/* Subtract 8 here because 'Neighbor' is
					 * 8 characters */
					vty_out(vty, "Neighbor");
					vty_out(vty, "%*s",
						max_neighbor_width - 8, " ");
					vty_out(vty,
						show_wide
							? BGP_SHOW_SUMMARY_HEADER_ALL_WIDE
							: BGP_SHOW_SUMMARY_HEADER_ALL);
				}

				memset(dn_flag, '\0', sizeof(dn_flag));
				if (peer_dynamic_neighbor(peer)) {
					dn_flag[0] = '*';
				}

				if (peer->hostname
				    && CHECK_FLAG(bgp->flags,
						  BGP_FLAG_SHOW_HOSTNAME))
					len = vty_out(vty, "%s%s(%s)", dn_flag,
						      peer->hostname,
						      peer->host);
				else
					len = vty_out(vty, "%s%s", dn_flag, peer->host);

				/* pad the neighbor column with spaces */
				if (len < max_neighbor_width)
					vty_out(vty, "%*s", max_neighbor_width - len,
						" ");

				atomic_size_t outq_count, inq_count;
				outq_count =
					atomic_load_explicit(&peer->connection
								      ->obuf
								      ->count,
							     memory_order_relaxed);
				inq_count =
					atomic_load_explicit(&peer->connection
								      ->ibuf
								      ->count,
							     memory_order_relaxed);

				vty_out(vty, "4");
				vty_out(vty, ASN_FORMAT_SPACE(bgp->asnotation),
					&peer->as);
				if (show_wide)
					vty_out(vty,
						ASN_FORMAT_SPACE(
							bgp->asnotation),
						peer->change_local_as
							? &peer->change_local_as
							: &peer->local_as);
				vty_out(vty,
					" %9u %9u %8" PRIu64 " %4zu %4zu %8s",
					PEER_TOTAL_RX(peer),
					PEER_TOTAL_TX(peer),
					(paf && PAF_SUBGRP(paf))
						? paf->subgroup->version
						: 0,
					inq_count, outq_count,
					peer_uptime(peer->uptime, timebuf,
						    BGP_UPTIME_LEN, 0, NULL));

				if (peer_established(peer->connection)) {
					if (peer->afc_recv[afi][safi]) {
						if (CHECK_FLAG(
							    bgp->flags,
							    BGP_FLAG_EBGP_REQUIRES_POLICY)
						    && !bgp_inbound_policy_exists(
							    peer, filter))
							vty_out(vty, " %12s",
								"(Policy)");
						else
							vty_out(vty,
								" %12u",
								peer->pcount
									[afi]
									[pfx_rcd_safi]);
					} else {
						vty_out(vty, "        NoNeg");
					}

					if (paf && PAF_SUBGRP(paf)) {
						if (CHECK_FLAG(
							    bgp->flags,
							    BGP_FLAG_EBGP_REQUIRES_POLICY)
						    && !bgp_outbound_policy_exists(
							    peer, filter))
							vty_out(vty, " %8s",
								"(Policy)");
						else
							vty_out(vty,
								" %8u",
								(PAF_SUBGRP(
									 paf))
									->scount);
					} else {
						vty_out(vty, "    NoNeg");
					}
				} else {
					if (CHECK_FLAG(peer->flags,
						       PEER_FLAG_SHUTDOWN)
					    || CHECK_FLAG(peer->bgp->flags,
							  BGP_FLAG_SHUTDOWN))
						vty_out(vty, " Idle (Admin)");
					else if (CHECK_FLAG(
							    peer->sflags,
							    PEER_STATUS_PREFIX_OVERFLOW))
						vty_out(vty, " Idle (PfxCt)");
					else
						vty_out(vty, " %12s",
							lookup_msg(bgp_status_msg,
								   peer->connection
									   ->status,
								   NULL));

					vty_out(vty, " %8u", 0);
				}
				/* Make sure `Desc` column is the latest in
				 * the output.
				 * If the description is not set, try
				 * to print the software version if the
				 * capability is enabled and received.
				 */
				if (peer->desc)
					vty_out(vty, " %s",
						bgp_peer_description_stripped(
							peer->desc,
							show_wide ? 64 : 20));
				else if (peer->soft_version) {
					vty_out(vty, " %s",
						bgp_peer_description_stripped(
							peer->soft_version,
							show_wide ? 64 : 20));
				} else {
					vty_out(vty, " N/A");
				}
				vty_out(vty, "\n");
			}

		}
	}

	/*
	 * An instance with no peers in this AFI/SAFI never reached the header
	 * block inside the loop above, but it can still have advertisement-delay
	 * state to report: the timer is started by the first peer to reach
	 * Established in any instance.
	 */
	if (!count && bgp_advertisement_delay_configured(bgp)) {
		bgp_show_summary_instance_header(vty, bgp, json, use_json);
		bgp_show_summary_advertisement_delay(vty, bgp, json, use_json);
	}

	if (use_json) {
		json_object_object_add(json, "peers", json_peers);
		json_object_int_add(json, "failedPeers", failed_count);
		json_object_int_add(json, "displayedPeers",
				    count - filtered_count);
		json_object_int_add(json, "totalPeers", count);
		json_object_int_add(json, "dynamicPeers", dn_count);

		if (!show_failed)
			bgp_show_bestpath_json(bgp, json);

		vty_json(vty, json);
	} else {
		if (count) {
			if (filtered_count == count)
				vty_out(vty, "\n%% No matching neighbor\n");
			else {
				if (show_failed)
					vty_out(vty, "\nDisplayed neighbors %d",
						failed_count);
				else if (as_type != AS_UNSPECIFIED || as
					 || fpeer || show_established)
					vty_out(vty, "\nDisplayed neighbors %d",
						count - filtered_count);

				vty_out(vty, "\nTotal number of neighbors %d\n",
					count);
			}
		} else {
			vty_out(vty, "No %s neighbor is configured\n",
				get_afi_safi_str(afi, safi, false));
		}

		if (dn_count) {
			vty_out(vty, "* - dynamic neighbor\n");
			vty_out(vty, "%d dynamic neighbor(s), limit %d\n",
				dn_count, bgp->dynamic_neighbors_limit);
		}
	}

	return CMD_SUCCESS;
}

/*
 * Number of peers configured in this BGP instance, counted once per peer
 * regardless of how many address families it is activated in.
 */
static uint32_t bgp_instance_peer_count(struct bgp *bgp)
{
	struct listnode *node;
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	uint32_t count = 0;

	for (ALL_LIST_ELEMENTS_RO(bgp->peer, node, peer)) {
		bool activated = false;

		if (!peer_is_config_node(peer))
			continue;

		FOREACH_AFI_SAFI (afi, safi) {
			if (peer->afc[afi][safi])
				activated = true;
		}

		if (activated)
			count++;
	}

	return count;
}

static void bgp_show_summary_afi_safi(struct vty *vty, struct bgp *bgp, int afi,
				      int safi, struct peer *fpeer, int as_type,
				      as_t as, uint16_t show_flags)
{
	int is_first = 1;
	int afi_wildcard = (afi == AFI_MAX);
	int safi_wildcard = (safi == SAFI_MAX);
	int is_wildcard = (afi_wildcard || safi_wildcard);
	bool nbr_output = false;
	bool use_json = CHECK_FLAG(show_flags, BGP_SHOW_OPT_JSON);
	/* A VRF with no peers of its own still has to report its
	 * advertisement-delay state; show it once, under IPv4 unicast.
	 */
	bool adv_delay_only = bgp_advertisement_delay_configured(bgp) &&
			      !bgp_instance_peer_count(bgp);

	if (use_json && is_wildcard)
		vty_out(vty, "{\n");
	if (afi_wildcard)
		afi = 1; /* AFI_IP */
	while (afi < AFI_MAX) {
		if (safi_wildcard)
			safi = 1; /* SAFI_UNICAST */
		while (safi < SAFI_MAX) {
			if (bgp_afi_safi_peer_exists(bgp, afi, safi) ||
			    (adv_delay_only && afi == AFI_IP && safi == SAFI_UNICAST)) {
				nbr_output = true;

				if (is_wildcard) {
					/*
					 * So limit output to those afi/safi
					 * pairs that
					 * actually have something interesting in
					 * them
					 */
					if (use_json) {
						if (!is_first)
							vty_out(vty, ",\n");
						else
							is_first = 0;

						vty_out(vty, "\"%s\":",
							get_afi_safi_str(afi,
									 safi,
									 true));
					} else {
						vty_out(vty, "\n%s Summary:\n",
							get_afi_safi_str(afi,
									 safi,
									 false));
					}
				}
				bgp_show_summary(vty, bgp, afi, safi, fpeer,
						 as_type, as, show_flags);
			}
			safi++;
			if (!safi_wildcard)
				safi = SAFI_MAX;
		}
		afi++;
		if (!afi_wildcard)
			afi = AFI_MAX;
	}

	if (use_json && is_wildcard)
		vty_out(vty, "}\n");
	else if (!nbr_output) {
		if (use_json)
			vty_out(vty, "{}\n");
		else
			vty_out(vty, "%% No BGP neighbors found in %s\n",
				bgp->name_pretty);
	}
}

static void bgp_show_all_instances_summary_vty(struct vty *vty, afi_t afi,
					       safi_t safi, const char *neighbor,
					       enum peer_asn_type as_type,
					       as_t as, uint16_t show_flags)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;
	struct peer *fpeer = NULL;
	int is_first = 1;
	bool nbr_output = false;
	bool use_json = CHECK_FLAG(show_flags, BGP_SHOW_OPT_JSON);

	if (use_json)
		vty_out(vty, "{\n");

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		if (CHECK_FLAG(bgp->vrf_flags, BGP_VRF_AUTO))
			continue;

		if (IS_BGP_INSTANCE_HIDDEN(bgp))
			continue;

		nbr_output = true;
		if (use_json) {
			if (!is_first)
				vty_out(vty, ",\n");
			else
				is_first = 0;

			vty_out(vty, "\"%s\":",
				(bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)
					? VRF_DEFAULT_NAME
					: bgp->name);
		}
		if (neighbor) {
			fpeer = peer_lookup_in_view(vty, bgp, neighbor,
						    use_json);
			if (!fpeer)
				continue;
		}
		bgp_show_summary_afi_safi(vty, bgp, afi, safi, fpeer, as_type,
					  as, show_flags);
	}

	if (use_json)
		vty_out(vty, "}\n");
	else if (!nbr_output)
		vty_out(vty, "%% BGP instance not found\n");
}

int bgp_show_summary_vty(struct vty *vty, const char *name, afi_t afi,
			 safi_t safi, const char *neighbor,
			 enum peer_asn_type as_type, as_t as,
			 uint16_t show_flags)
{
	struct bgp *bgp;
	bool use_json = CHECK_FLAG(show_flags, BGP_SHOW_OPT_JSON);
	struct peer *fpeer = NULL;

	if (name) {
		if (strmatch(name, "all")) {
			bgp_show_all_instances_summary_vty(vty, afi, safi,
							   neighbor, as_type,
							   as, show_flags);
			return CMD_SUCCESS;
		} else {
			bgp = bgp_lookup_by_name(name);

			if (!bgp) {
				if (use_json)
					vty_out(vty, "{}\n");
				else
					vty_out(vty,
						"%% BGP instance not found\n");
				return CMD_WARNING;
			}

			if (neighbor) {
				fpeer = peer_lookup_in_view(vty, bgp, neighbor,
							    use_json);
				if (!fpeer)
					return CMD_WARNING;
			}
			bgp_show_summary_afi_safi(vty, bgp, afi, safi, fpeer,
						  as_type, as, show_flags);
			return CMD_SUCCESS;
		}
	}

	bgp = bgp_get_default();

	if (bgp) {
		if (neighbor) {
			fpeer = peer_lookup_in_view(vty, bgp, neighbor,
						    use_json);
			if (!fpeer)
				return CMD_WARNING;
		}
		bgp_show_summary_afi_safi(vty, bgp, afi, safi, fpeer, as_type,
					  as, show_flags);
	} else {
		if (use_json)
			vty_out(vty, "{}\n");
		else
			vty_out(vty, "%% BGP instance not found\n");
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

/* `show [ip] bgp summary' commands. */
DEFPY(show_ip_bgp_summary, show_ip_bgp_summary_cmd,
      "show [ip] bgp [<view|vrf> VIEWVRFNAME] [" BGP_AFI_CMD_STR
      " [" BGP_SAFI_WITH_LABEL_CMD_STR
      "]] [all$all] summary [established|failed] [<neighbor <A.B.C.D|X:X::X:X|WORD>|remote-as <ASNUM|internal|external>>] [terse] [wide] [json$uj]",
      SHOW_STR IP_STR BGP_STR BGP_INSTANCE_HELP_STR BGP_AFI_HELP_STR
	      BGP_SAFI_WITH_LABEL_HELP_STR
      "Display the entries for all address families\n"
      "Summary of BGP neighbor status\n"
      "Show only sessions in Established state\n"
      "Show only sessions not in Established state\n"
      "Show only the specified neighbor session\n"
      "Neighbor to display information about\n"
      "Neighbor to display information about\n"
      "Neighbor on BGP configured interface\n"
      "Show only the specified remote AS sessions\n" AS_STR
      "Internal (iBGP) AS sessions\n"
      "External (eBGP) AS sessions\n"
      "Shorten the information on BGP instances\n"
      "Increase table width for longer output\n" JSON_STR)
{
	char *vrf = NULL;
	afi_t afi = AFI_MAX;
	safi_t safi = SAFI_MAX;
	as_t as = 0; /* 0 means AS filter not set */
	int as_type = AS_UNSPECIFIED;
	uint16_t show_flags = 0;

	int idx = 0;

	/* show [ip] bgp */
	if (!all && argv_find(argv, argc, "ip", &idx))
		afi = AFI_IP;
	/* [<vrf> VIEWVRFNAME] */
	if (argv_find(argv, argc, "vrf", &idx)) {
		vrf = argv[idx + 1]->arg;
		if (vrf && strmatch(vrf, VRF_DEFAULT_NAME))
			vrf = NULL;
	} else if (argv_find(argv, argc, "view", &idx))
		/* [<view> VIEWVRFNAME] */
		vrf = argv[idx + 1]->arg;
	/* ["BGP_AFI_CMD_STR" ["BGP_SAFI_CMD_STR"]] */
	if (argv_find_and_parse_afi(argv, argc, &idx, &afi)) {
		argv_find_and_parse_safi(argv, argc, &idx, &safi);
	}

	if (argv_find(argv, argc, "failed", &idx))
		SET_FLAG(show_flags, BGP_SHOW_OPT_FAILED);

	if (argv_find(argv, argc, "established", &idx))
		SET_FLAG(show_flags, BGP_SHOW_OPT_ESTABLISHED);

	if (argv_find(argv, argc, "remote-as", &idx)) {
		if (argv[idx + 1]->arg[0] == 'i')
			as_type = AS_INTERNAL;
		else if (argv[idx + 1]->arg[0] == 'e')
			as_type = AS_EXTERNAL;
		else if (argv[idx + 1]->arg[0] == 'a')
			as_type = AS_AUTO;
		else if (!asn_str2asn(argv[idx + 1]->arg, &as)) {
			vty_out(vty,
				"%% Invalid neighbor remote-as value: %s\n",
				argv[idx + 1]->arg);
			return CMD_SUCCESS;
		}
	}

	if (argv_find(argv, argc, "terse", &idx))
		SET_FLAG(show_flags, BGP_SHOW_OPT_TERSE);

	if (argv_find(argv, argc, "wide", &idx))
		SET_FLAG(show_flags, BGP_SHOW_OPT_WIDE);

	if (argv_find(argv, argc, "json", &idx))
		SET_FLAG(show_flags, BGP_SHOW_OPT_JSON);

	return bgp_show_summary_vty(vty, vrf, afi, safi, neighbor, as_type, as,
				    show_flags);
}

const char *get_afi_safi_str(afi_t afi, safi_t safi, bool for_json)
{
	if (for_json)
		return get_afi_safi_json_str(afi, safi);
	else
		return get_afi_safi_vty_str(afi, safi);
}


static void bgp_show_peer_afi_orf_cap(struct vty *vty, struct peer *p,
				      afi_t afi, safi_t safi,
				      uint16_t adv_smcap, uint16_t adv_rmcap,
				      uint16_t rcv_smcap, uint16_t rcv_rmcap,
				      bool use_json, json_object *json_pref)
{
	/* Send-Mode */
	if (CHECK_FLAG(p->af_cap[afi][safi], adv_smcap)
	    || CHECK_FLAG(p->af_cap[afi][safi], rcv_smcap)) {
		if (use_json) {
			if (CHECK_FLAG(p->af_cap[afi][safi], adv_smcap)
			    && CHECK_FLAG(p->af_cap[afi][safi], rcv_smcap))
				json_object_string_add(json_pref, "sendMode",
						       "advertisedAndReceived");
			else if (CHECK_FLAG(p->af_cap[afi][safi], adv_smcap))
				json_object_string_add(json_pref, "sendMode",
						       "advertised");
			else if (CHECK_FLAG(p->af_cap[afi][safi], rcv_smcap))
				json_object_string_add(json_pref, "sendMode",
						       "received");
		} else {
			vty_out(vty, "      Send-mode: ");
			if (CHECK_FLAG(p->af_cap[afi][safi], adv_smcap))
				vty_out(vty, "advertised");
			if (CHECK_FLAG(p->af_cap[afi][safi], rcv_smcap))
				vty_out(vty, "%sreceived",
					CHECK_FLAG(p->af_cap[afi][safi],
						   adv_smcap)
						? ", "
						: "");
			vty_out(vty, "\n");
		}
	}

	/* Receive-Mode */
	if (CHECK_FLAG(p->af_cap[afi][safi], adv_rmcap)
	    || CHECK_FLAG(p->af_cap[afi][safi], rcv_rmcap)) {
		if (use_json) {
			if (CHECK_FLAG(p->af_cap[afi][safi], adv_rmcap)
			    && CHECK_FLAG(p->af_cap[afi][safi], rcv_rmcap))
				json_object_string_add(json_pref, "recvMode",
						       "advertisedAndReceived");
			else if (CHECK_FLAG(p->af_cap[afi][safi], adv_rmcap))
				json_object_string_add(json_pref, "recvMode",
						       "advertised");
			else if (CHECK_FLAG(p->af_cap[afi][safi], rcv_rmcap))
				json_object_string_add(json_pref, "recvMode",
						       "received");
		} else {
			vty_out(vty, "      Receive-mode: ");
			if (CHECK_FLAG(p->af_cap[afi][safi], adv_rmcap))
				vty_out(vty, "advertised");
			if (CHECK_FLAG(p->af_cap[afi][safi], rcv_rmcap))
				vty_out(vty, "%sreceived",
					CHECK_FLAG(p->af_cap[afi][safi],
						   adv_rmcap)
						? ", "
						: "");
			vty_out(vty, "\n");
		}
	}
}

static void bgp_show_neighnor_graceful_restart_flags(struct vty *vty,
						     struct peer *p,
						     json_object *json)
{
	bool rbit = false;
	bool nbit = false;

	if (CHECK_FLAG(p->cap, PEER_CAP_RESTART_ADV) &&
	    (CHECK_FLAG(p->cap, PEER_CAP_RESTART_RCV)) &&
	    (peer_established(p->connection))) {
		rbit = CHECK_FLAG(p->cap, PEER_CAP_GRACEFUL_RESTART_R_BIT_RCV);
		nbit = CHECK_FLAG(p->cap, PEER_CAP_GRACEFUL_RESTART_N_BIT_RCV);
	}

	if (json) {
		json_object_boolean_add(json, "rBit", rbit);
		json_object_boolean_add(json, "nBit", nbit);
	} else {
		vty_out(vty, "\n    R bit: %s", rbit ? "True" : "False");
		vty_out(vty, "\n    N bit: %s\n", nbit ? "True" : "False");
	}
}

static void bgp_show_neighbor_graceful_restart_remote_mode(struct vty *vty,
							   struct peer *peer,
							   json_object *json)
{
	const char *mode = "NotApplicable";

	if (CHECK_FLAG(peer->cap, PEER_CAP_RESTART_ADV) &&
	    (peer_established(peer->connection))) {
		if ((peer->nsf_af_count == 0)
		    && !CHECK_FLAG(peer->cap, PEER_CAP_RESTART_RCV)) {

			mode = "Disable";

		} else if (peer->nsf_af_count == 0
			   && CHECK_FLAG(peer->cap, PEER_CAP_RESTART_RCV)) {

			mode = "Helper";

		} else if (peer->nsf_af_count != 0
			   && CHECK_FLAG(peer->cap, PEER_CAP_RESTART_RCV)) {

			mode = "Restart";
		}
	}

	if (json)
		json_object_string_add(json, "remoteGrMode", mode);
	else
		vty_out(vty, "    Remote GR Mode: %s\n", mode);
}

static void bgp_show_neighbor_graceful_restart_local_mode(struct vty *vty,
							  struct peer *p,
							  json_object *json)
{
	const char *mode = "Invalid";

	if (bgp_peer_gr_mode_get(p) == PEER_HELPER)
		mode = "Helper";
	else if (bgp_peer_gr_mode_get(p) == PEER_GR)
		mode = "Restart";
	else if (bgp_peer_gr_mode_get(p) == PEER_DISABLE)
		mode = "Disable";
	else if (bgp_peer_gr_mode_get(p) == PEER_GLOBAL_INHERIT) {
		if (bgp_global_gr_mode_get(p->bgp) == GLOBAL_HELPER)
			mode = "Helper*";
		else if (bgp_global_gr_mode_get(p->bgp) == GLOBAL_GR)
			mode = "Restart*";
		else if (bgp_global_gr_mode_get(p->bgp) == GLOBAL_DISABLE)
			mode = "Disable*";
		else
			mode = "Invalid*";
	}

	if (json)
		json_object_string_add(json, "localGrMode", mode);
	else
		vty_out(vty, "    Local GR Mode: %s\n", mode);
}

static void bgp_show_peer_gr_info_afi_safi(struct vty *vty, struct peer *peer, bool use_json,
					   json_object *json)
{
	afi_t afi;
	safi_t safi;
	json_object *json_afi_safi = NULL;
	json_object *json_timer = NULL;
	json_object *json_endofrib_status = NULL;
	bool eor_flag = false;

	FOREACH_AFI_SAFI_NSF (afi, safi) {
		if (!peer->afc[afi][safi])
			continue;

		if (!CHECK_FLAG(peer->cap, PEER_CAP_RESTART_ADV) ||
		    !CHECK_FLAG(peer->cap, PEER_CAP_RESTART_RCV))
			continue;

		if (json) {
			json_afi_safi = json_object_new_object();
			json_endofrib_status = json_object_new_object();
			json_timer = json_object_new_object();
		}

		if (peer->eor_stime[afi][safi] >= peer->pkt_stime[afi][safi])
			eor_flag = true;
		else
			eor_flag = false;

		if (!json) {
			vty_out(vty, "    %s:\n",
				get_afi_safi_str(afi, safi, false));

			vty_out(vty, "      F bit: ");
		}

		if (peer->nsf[afi][safi] &&
		    CHECK_FLAG(peer->af_cap[afi][safi],
			       PEER_CAP_RESTART_AF_PRESERVE_RCV)) {

			if (json) {
				json_object_boolean_true_add(json_afi_safi,
							     "fBit");
			} else
				vty_out(vty, "True\n");
		} else {
			if (json)
				json_object_boolean_false_add(json_afi_safi,
							      "fBit");
			else
				vty_out(vty, "False\n");
		}

		if (!json)
			vty_out(vty, "      End-of-RIB sent: ");

		if (CHECK_FLAG(peer->af_sflags[afi][safi],
			       PEER_STATUS_EOR_SEND)) {
			if (json) {
				json_object_boolean_true_add(
					json_endofrib_status, "endOfRibSend");

				PRINT_EOR_JSON(eor_flag);
			} else {
				vty_out(vty, "Yes\n");
				vty_out(vty,
					"      End-of-RIB sent after update: ");

				PRINT_EOR(eor_flag);
			}
		} else {
			if (json) {
				json_object_boolean_false_add(
					json_endofrib_status, "endOfRibSend");
				json_object_boolean_false_add(
					json_endofrib_status,
					"endOfRibSentAfterUpdate");
			} else {
				vty_out(vty, "No\n");
				vty_out(vty,
					"      End-of-RIB sent after update: ");
				vty_out(vty, "No\n");
			}
		}

		if (!json)
			vty_out(vty, "      End-of-RIB received: ");

		if (CHECK_FLAG(peer->af_sflags[afi][safi],
			       PEER_STATUS_EOR_RECEIVED)) {
			if (json)
				json_object_boolean_true_add(
					json_endofrib_status, "endOfRibRecv");
			else
				vty_out(vty, "Yes\n");
		} else {
			if (json)
				json_object_boolean_false_add(
					json_endofrib_status, "endOfRibRecv");
			else
				vty_out(vty, "No\n");
		}

		if (json) {
			json_object_int_add(json_timer, "stalePathTimer",
					    peer->bgp->stalepath_time);
			json_object_int_add(json_timer, "llgrStaleTime",
					    peer->llgr[afi][safi].stale_time);

			if (event_is_scheduled(peer->connection->t_gr_stale)) {
				json_object_int_add(json_timer,
						    "stalePathTimerRemaining",
						    event_timer_remain_second(
							    peer->connection
								    ->t_gr_stale));
			}

			/* Display Configured Selection
			 * Deferral only when when
			 * Gr mode is enabled.
			 */
			if (CHECK_FLAG(peer->flags,
				       PEER_FLAG_GRACEFUL_RESTART)) {
				json_object_int_add(json_timer, "selectionDeferralTimer",
						    peer->bgp->select_defer_time);
			}

			if (peer->bgp->gr_info[afi][safi].t_select_deferral !=
			    NULL) {

				json_object_int_add(
					json_timer,
					"selectionDeferralTimerRemaining",
					event_timer_remain_second(
						peer->bgp->gr_info[afi][safi]
							.t_select_deferral));
			}

			if (peer->bgp->gr_multihop_peer_exists) {
				if (CHECK_FLAG(peer->flags, PEER_FLAG_GRACEFUL_RESTART))
					json_object_int_add(json_timer,
							    "selectionDeferralTier2Timer",
							    peer->bgp->select_defer_time);

				if (peer->bgp->gr_info[afi][safi].t_select_deferral_tier2 != NULL)
					json_object_int_add(json_timer,
							    "selectionDeferralTier2TimerRemaining",
							    event_timer_remain_second(
								    peer->bgp->gr_info[afi][safi]
									    .t_select_deferral_tier2));
			}
		} else {
			vty_out(vty, "      Timers:\n");
			vty_out(vty,
				"        Configured Stale Path Time(sec): %u\n",
				peer->bgp->stalepath_time);

			if (event_is_scheduled(peer->connection->t_gr_stale))
				vty_out(vty,
					"      Stale Path Remaining(sec): %ld\n",
					event_timer_remain_second(
						peer->connection->t_gr_stale));
			/* Display Configured Selection
			 * Deferral only when when
			 * Gr mode is enabled.
			 */
			if (CHECK_FLAG(peer->flags, PEER_FLAG_GRACEFUL_RESTART))
				vty_out(vty,
					"        Configured Selection Deferral Time(sec): %u\n",
					peer->bgp->select_defer_time);

			vty_out(vty, "        LLGR Stale Path Time(sec): %u\n",
				peer->llgr[afi][safi].stale_time);

			if (peer->bgp->gr_info[afi][safi].t_select_deferral !=
			    NULL)
				vty_out(vty,
					"        Selection Deferral Time Remaining(sec): %ld\n",
					event_timer_remain_second(
						peer->bgp->gr_info[afi][safi]
							.t_select_deferral));
			if (peer->bgp->gr_multihop_peer_exists) {
				vty_out(vty, "        Multihop GR peer exists\n");
				if (peer->bgp->gr_info[afi][safi].t_select_deferral_tier2 != NULL)
					vty_out(vty,
						"        Selection Deferral Tier2 Time Remaining(sec): %ld\n",
						event_timer_remain_second(
							peer->bgp->gr_info[afi][safi]
								.t_select_deferral_tier2));
			}
		}
		if (json) {
			json_object_object_add(json_afi_safi, "endOfRibStatus",
					       json_endofrib_status);
			json_object_object_add(json_afi_safi, "timers",
					       json_timer);
			json_object_object_add(
				json, get_afi_safi_str(afi, safi, true),
				json_afi_safi);
		}
	}
}

static void bgp_show_neighbor_graceful_restart_time(struct vty *vty,
						    struct peer *p,
						    json_object *json)
{
	if (json) {
		json_object *json_timer = NULL;

		json_timer = json_object_new_object();

		json_object_int_add(json_timer, "configuredRestartTimer",
				    p->bgp->restart_time);
		json_object_int_add(json_timer, "configuredLlgrStaleTime",
				    p->bgp->llgr_stale_time);

		json_object_int_add(json_timer, "receivedRestartTimer",
				    p->v_gr_restart);

		if (event_is_scheduled(p->connection->t_gr_restart))
			json_object_int_add(json_timer, "restartTimerRemaining",
					    event_timer_remain_second(
						    p->connection->t_gr_restart));
		if (event_is_scheduled(p->connection->t_gr_stale))
			json_object_int_add(json_timer, "gracefulStalepathTimerSec",
					    event_timer_remain_second(p->connection->t_gr_stale));

		json_object_object_add(json, "timers", json_timer);
	} else {

		vty_out(vty, "    Timers:\n");
		vty_out(vty, "      Configured Restart Time(sec): %u\n",
			p->bgp->restart_time);

		vty_out(vty, "      Received Restart Time(sec): %u\n",
			p->v_gr_restart);
		vty_out(vty, "      Configured LLGR Stale Path Time(sec): %u\n",
			p->bgp->llgr_stale_time);
		if (event_is_scheduled(p->connection->t_gr_restart))
			vty_out(vty, "      Restart Time Remaining(sec): %ld\n",
				event_timer_remain_second(
					p->connection->t_gr_restart));
	}
}

static void bgp_show_peer_afi(struct vty *vty, struct peer *p, afi_t afi,
			      safi_t safi, bool use_json,
			      json_object *json_neigh)
{
	int pfx_rcd_safi;
	struct bgp_filter *filter;
	struct peer_af *paf;
	char orf_pfx_name[BUFSIZ];
	int orf_pfx_count;
	json_object *json_af = NULL;
	json_object *json_prefA = NULL;
	json_object *json_addr = NULL;
	json_object *json_advmap = NULL;

	if (safi == SAFI_LABELED_UNICAST)
		pfx_rcd_safi = SAFI_UNICAST;
	else
		pfx_rcd_safi = safi;

	if (use_json) {
		json_addr = json_object_new_object();
		json_af = json_object_new_object();
		filter = &p->filter[afi][safi];

		if (peer_group_active(p))
			json_object_string_add(json_addr, "peerGroupMember",
					       p->group->name);

		paf = peer_af_find(p, afi, safi);
		if (paf && PAF_SUBGRP(paf)) {
			json_object_int_add(json_addr, "updateGroupId",
					    PAF_UPDGRP(paf)->id);
			json_object_int_add(json_addr, "subGroupId",
					    PAF_SUBGRP(paf)->id);
			json_object_int_add(json_addr, "packetQueueLength",
					    bpacket_queue_virtual_length(paf));
		}

		/* weight */
		if (peergroup_af_flag_check(p, afi, safi, PEER_FLAG_WEIGHT))
			json_object_int_add(json_addr, "weight", p->weight[afi][safi]);

		if (CHECK_FLAG(p->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_SM_ADV)
		    || CHECK_FLAG(p->af_cap[afi][safi],
				  PEER_CAP_ORF_PREFIX_SM_RCV)
		    || CHECK_FLAG(p->af_cap[afi][safi],
				  PEER_CAP_ORF_PREFIX_RM_ADV)
		    || CHECK_FLAG(p->af_cap[afi][safi],
				  PEER_CAP_ORF_PREFIX_RM_RCV)) {
			json_object_int_add(json_af, "orfType",
					    ORF_TYPE_PREFIX);
			json_prefA = json_object_new_object();
			bgp_show_peer_afi_orf_cap(vty, p, afi, safi,
						  PEER_CAP_ORF_PREFIX_SM_ADV,
						  PEER_CAP_ORF_PREFIX_RM_ADV,
						  PEER_CAP_ORF_PREFIX_SM_RCV,
						  PEER_CAP_ORF_PREFIX_RM_RCV,
						  use_json, json_prefA);
			json_object_object_add(json_af, "orfPrefixList",
					       json_prefA);
		}

		if (CHECK_FLAG(p->af_cap[afi][safi],
			       PEER_CAP_ORF_PREFIX_SM_ADV) ||
		    CHECK_FLAG(p->af_cap[afi][safi],
			       PEER_CAP_ORF_PREFIX_SM_RCV) ||
		    CHECK_FLAG(p->af_cap[afi][safi],
			       PEER_CAP_ORF_PREFIX_RM_ADV) ||
		    CHECK_FLAG(p->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_RM_RCV))
			json_object_object_add(json_addr, "afDependentCap",
					       json_af);
		else
			json_object_free(json_af);

		peer_orf_plist_name(p, afi, safi, orf_pfx_name, sizeof(orf_pfx_name));
		orf_pfx_count = prefix_bgp_show_prefix_list(
			NULL, afi, orf_pfx_name, use_json);

		if (CHECK_FLAG(p->af_sflags[afi][safi],
			       PEER_STATUS_ORF_PREFIX_SEND)
		    || orf_pfx_count) {
			if (CHECK_FLAG(p->af_sflags[afi][safi],
				       PEER_STATUS_ORF_PREFIX_SEND))
				json_object_boolean_true_add(json_neigh,
							     "orfSent");
			if (orf_pfx_count)
				json_object_int_add(json_addr, "orfRecvCounter",
						    orf_pfx_count);
		}
		if (CHECK_FLAG(p->af_sflags[afi][safi],
			       PEER_STATUS_ORF_WAIT_REFRESH))
			json_object_string_add(
				json_addr, "orfFirstUpdate",
				"deferredUntilORFOrRouteRefreshRecvd");

		if (CHECK_FLAG(p->af_flags[afi][safi],
			       PEER_FLAG_REFLECTOR_CLIENT))
			json_object_boolean_true_add(json_addr,
						     "routeReflectorClient");
		if (CHECK_FLAG(p->af_flags[afi][safi],
			       PEER_FLAG_RSERVER_CLIENT))
			json_object_boolean_true_add(json_addr,
						     "routeServerClient");
		if (CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_SOFT_RECONFIG))
			json_object_boolean_true_add(json_addr,
						     "inboundSoftConfigPermit");

		if (CHECK_FLAG(p->af_flags[afi][safi],
			       PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE))
			json_object_boolean_true_add(
				json_addr,
				"privateAsNumsAllReplacedInUpdatesToNbr");
		else if (CHECK_FLAG(p->af_flags[afi][safi],
				    PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE))
			json_object_boolean_true_add(
				json_addr,
				"privateAsNumsReplacedInUpdatesToNbr");
		else if (CHECK_FLAG(p->af_flags[afi][safi],
				    PEER_FLAG_REMOVE_PRIVATE_AS_ALL))
			json_object_boolean_true_add(
				json_addr,
				"privateAsNumsAllRemovedInUpdatesToNbr");
		else if (CHECK_FLAG(p->af_flags[afi][safi],
				    PEER_FLAG_REMOVE_PRIVATE_AS))
			json_object_boolean_true_add(
				json_addr,
				"privateAsNumsRemovedInUpdatesToNbr");

		if (CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_ALLOWAS_IN)) {
			if (CHECK_FLAG(p->af_flags[afi][safi],
				       PEER_FLAG_ALLOWAS_IN_ORIGIN))
				json_object_boolean_true_add(json_addr,
							     "allowAsInOrigin");
			else
				json_object_int_add(json_addr, "allowAsInCount",
						    p->allowas_in[afi][safi]);

			if (p->allowas_in_rmap[afi][safi].name)
				json_object_string_add(json_addr, "allowAsInRouteMap",
						       p->allowas_in_rmap[afi][safi].name);
		}

		if (p->addpath_type[afi][safi] != BGP_ADDPATH_NONE)
			json_object_boolean_true_add(
				json_addr,
				bgp_addpath_names(p->addpath_type[afi][safi])
					->type_json_name);

		if (CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_AS_OVERRIDE))
			json_object_string_add(json_addr,
					       "overrideASNsInOutboundUpdates",
					       "ifAspathEqualRemoteAs");

		json_object_boolean_add(json_addr, "routerAlwaysNextHop",
			CHECK_FLAG(p->af_flags[afi][safi],
				PEER_FLAG_NEXTHOP_SELF) ||
			CHECK_FLAG(p->af_flags[afi][safi],
					PEER_FLAG_FORCE_NEXTHOP_SELF));

		json_object_boolean_add(json_addr, "forceRouterAlwaysNextHop",
			CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_FORCE_NEXTHOP_SELF));

		if (CHECK_FLAG(p->af_flags[afi][safi],
			       PEER_FLAG_AS_PATH_UNCHANGED))
			json_object_boolean_true_add(
				json_addr, "unchangedAsPathPropogatedToNbr");
		if (CHECK_FLAG(p->af_flags[afi][safi],
			       PEER_FLAG_NEXTHOP_UNCHANGED))
			json_object_boolean_true_add(
				json_addr, "unchangedNextHopPropogatedToNbr");
		if (CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_MED_UNCHANGED))
			json_object_boolean_true_add(
				json_addr, "unchangedMedPropogatedToNbr");
		if (CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_SEND_COMMUNITY) ||
		    CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_SEND_LARGE_COMMUNITY) ||
		    CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_SEND_EXT_COMMUNITY)) {
			char comm_attri_sent_to_nbr[BGP_SEND_COMMUNITY_STR_SIZE] = { 0 };

			if (CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_SEND_COMMUNITY)) {
				strlcat(comm_attri_sent_to_nbr, "standard",
					sizeof(comm_attri_sent_to_nbr));
			}

			if (CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_SEND_EXT_COMMUNITY)) {
				if (strlen(comm_attri_sent_to_nbr) > 0) {
					strlcat(comm_attri_sent_to_nbr, "And",
						sizeof(comm_attri_sent_to_nbr));
				}
				strlcat(comm_attri_sent_to_nbr, "extended",
					sizeof(comm_attri_sent_to_nbr));
			}

			if (CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_SEND_LARGE_COMMUNITY)) {
				if (strlen(comm_attri_sent_to_nbr) > 0) {
					strlcat(comm_attri_sent_to_nbr, "And",
						sizeof(comm_attri_sent_to_nbr));
				}
				strlcat(comm_attri_sent_to_nbr, "large",
					sizeof(comm_attri_sent_to_nbr));
			}

			json_object_string_add(json_addr, "commAttriSentToNbr",
					       comm_attri_sent_to_nbr);
		}
		if (CHECK_FLAG(p->af_flags[afi][safi],
			       PEER_FLAG_DEFAULT_ORIGINATE)) {
			if (p->default_rmap[afi][safi].name)
				json_object_string_add(
					json_addr, "defaultRouteMap",
					p->default_rmap[afi][safi].name);

			if (paf && PAF_SUBGRP(paf) && PAF_SUBGRP(paf)->default_originate_attr)
				json_object_boolean_true_add(json_addr,
							     "defaultSent");
			else
				json_object_boolean_true_add(json_addr,
							     "defaultNotSent");
		}

		if (afi == AFI_L2VPN && safi == SAFI_EVPN) {
			if (is_evpn_enabled())
				json_object_boolean_true_add(
					json_addr, "advertiseAllVnis");
		}

		if (filter->plist[FILTER_IN].name
		    || filter->dlist[FILTER_IN].name
		    || filter->aslist[FILTER_IN].name
		    || filter->map[RMAP_IN].name)
			json_object_boolean_true_add(json_addr,
						     "inboundPathPolicyConfig");
		if (filter->plist[FILTER_OUT].name
		    || filter->dlist[FILTER_OUT].name
		    || filter->aslist[FILTER_OUT].name
		    || filter->map[RMAP_OUT].name || filter->usmap.name)
			json_object_boolean_true_add(
				json_addr, "outboundPathPolicyConfig");

		/* prefix-list */
		if (filter->plist[FILTER_IN].name)
			json_object_string_add(json_addr,
					       "incomingUpdatePrefixFilterList",
					       filter->plist[FILTER_IN].name);
		if (filter->plist[FILTER_OUT].name)
			json_object_string_add(json_addr,
					       "outgoingUpdatePrefixFilterList",
					       filter->plist[FILTER_OUT].name);

		/* distribute-list */
		if (filter->dlist[FILTER_IN].name)
			json_object_string_add(
				json_addr, "incomingUpdateNetworkFilterList",
				filter->dlist[FILTER_IN].name);
		if (filter->dlist[FILTER_OUT].name)
			json_object_string_add(
				json_addr, "outgoingUpdateNetworkFilterList",
				filter->dlist[FILTER_OUT].name);

		/* filter-list. */
		if (filter->aslist[FILTER_IN].name)
			json_object_string_add(json_addr,
					       "incomingUpdateAsPathFilterList",
					       filter->aslist[FILTER_IN].name);
		if (filter->aslist[FILTER_OUT].name)
			json_object_string_add(json_addr,
					       "outgoingUpdateAsPathFilterList",
					       filter->aslist[FILTER_OUT].name);

		/* route-map. */
		if (filter->map[RMAP_IN].name)
			json_object_string_add(
				json_addr, "routeMapForIncomingAdvertisements",
				filter->map[RMAP_IN].name);
		if (filter->map[RMAP_OUT].name)
			json_object_string_add(
				json_addr, "routeMapForOutgoingAdvertisements",
				filter->map[RMAP_OUT].name);

		/* ebgp-requires-policy (inbound) */
		if (CHECK_FLAG(p->bgp->flags, BGP_FLAG_EBGP_REQUIRES_POLICY)
		    && !bgp_inbound_policy_exists(p, filter))
			json_object_string_add(
				json_addr, "inboundEbgpRequiresPolicy",
				"Inbound updates discarded due to missing policy");

		/* ebgp-requires-policy (outbound) */
		if (CHECK_FLAG(p->bgp->flags, BGP_FLAG_EBGP_REQUIRES_POLICY)
		    && (!bgp_outbound_policy_exists(p, filter)))
			json_object_string_add(
				json_addr, "outboundEbgpRequiresPolicy",
				"Outbound updates discarded due to missing policy");

		/* unsuppress-map */
		if (filter->usmap.name)
			json_object_string_add(json_addr,
					       "selectiveUnsuppressRouteMap",
					       filter->usmap.name);

		/* advertise-map */
		if (filter->advmap.aname) {
			json_advmap = json_object_new_object();
			json_object_string_add(json_advmap, "condition",
					       filter->advmap.condition
						       ? "EXIST"
						       : "NON_EXIST");
			json_object_string_add(json_advmap, "conditionMap",
					       filter->advmap.cname);
			json_object_string_add(json_advmap, "advertiseMap",
					       filter->advmap.aname);
			json_object_string_add(
				json_advmap, "advertiseStatus",
				filter->advmap.update_type ==
						UPDATE_TYPE_ADVERTISE
					? "Advertise"
					: "Withdraw");
			json_object_object_add(json_addr, "advertiseMap",
					       json_advmap);
		}

		/* Receive prefix count */
		json_object_int_add(json_addr, "acceptedPrefixCounter",
				    p->pcount[afi][pfx_rcd_safi]);
		if (paf && PAF_SUBGRP(paf))
			json_object_int_add(json_addr, "sentPrefixCounter",
						(PAF_SUBGRP(paf))->scount);

		json_object_int_add(json_addr, "receivedPrefixDup",
				    p->pcount_dup[afi][pfx_rcd_safi]);

		/* Maximum prefix */
		if (CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_MAX_PREFIX_OUT))
			json_object_int_add(json_addr, "prefixOutAllowedMax",
					    p->pmax_out[afi][safi]);

		/* Maximum prefix */
		if (CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_MAX_PREFIX)) {
			json_object_int_add(json_addr, "prefixAllowedMax",
					    p->pmax[afi][safi]);
			if (CHECK_FLAG(p->af_flags[afi][safi],
				       PEER_FLAG_MAX_PREFIX_WARNING))
				json_object_boolean_true_add(
					json_addr, "prefixAllowedMaxWarning");
			json_object_int_add(json_addr,
					    "prefixAllowedWarningThresh",
					    p->pmax_threshold[afi][safi]);
			if (p->pmax_restart[afi][safi])
				json_object_int_add(
					json_addr,
					"prefixAllowedRestartIntervalMsecs",
					p->pmax_restart[afi][safi] * 60000);
		}
		json_object_object_add(json_neigh,
				       get_afi_safi_str(afi, safi, true),
				       json_addr);

	} else {
		filter = &p->filter[afi][safi];

		vty_out(vty, " For address family: %s\n",
			get_afi_safi_str(afi, safi, false));

		if (peer_group_active(p))
			vty_out(vty, "  %s peer-group member\n",
				p->group->name);

		paf = peer_af_find(p, afi, safi);
		if (paf && PAF_SUBGRP(paf)) {
			vty_out(vty, "  Update group %" PRIu64", subgroup %" PRIu64 "\n",
				PAF_UPDGRP(paf)->id, PAF_SUBGRP(paf)->id);
			vty_out(vty, "  Packet Queue length %d\n",
				bpacket_queue_virtual_length(paf));
		} else {
			vty_out(vty, "  Not part of any update group\n");
		}
		if (peergroup_af_flag_check(p, afi, safi, PEER_FLAG_WEIGHT))
			vty_out(vty, "  Weight %lu\n", p->weight[afi][safi]);

		if (CHECK_FLAG(p->af_cap[afi][safi],
			       PEER_CAP_ORF_PREFIX_SM_ADV) ||
		    CHECK_FLAG(p->af_cap[afi][safi],
			       PEER_CAP_ORF_PREFIX_SM_RCV) ||
		    CHECK_FLAG(p->af_cap[afi][safi],
			       PEER_CAP_ORF_PREFIX_RM_ADV) ||
		    CHECK_FLAG(p->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_RM_RCV))
			vty_out(vty, "  AF-dependant capabilities:\n");

		if (CHECK_FLAG(p->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_SM_ADV)
		    || CHECK_FLAG(p->af_cap[afi][safi],
				  PEER_CAP_ORF_PREFIX_SM_RCV)
		    || CHECK_FLAG(p->af_cap[afi][safi],
				  PEER_CAP_ORF_PREFIX_RM_ADV)
		    || CHECK_FLAG(p->af_cap[afi][safi],
				  PEER_CAP_ORF_PREFIX_RM_RCV)) {
			vty_out(vty,
				"    Outbound Route Filter (ORF) type (%d) Prefix-list:\n",
				ORF_TYPE_PREFIX);
			bgp_show_peer_afi_orf_cap(
				vty, p, afi, safi, PEER_CAP_ORF_PREFIX_SM_ADV,
				PEER_CAP_ORF_PREFIX_RM_ADV,
				PEER_CAP_ORF_PREFIX_SM_RCV,
				PEER_CAP_ORF_PREFIX_RM_RCV, use_json, NULL);
		}

		peer_orf_plist_name(p, afi, safi, orf_pfx_name, sizeof(orf_pfx_name));
		orf_pfx_count = prefix_bgp_show_prefix_list(
			NULL, afi, orf_pfx_name, use_json);

		if (CHECK_FLAG(p->af_sflags[afi][safi],
			       PEER_STATUS_ORF_PREFIX_SEND)
		    || orf_pfx_count) {
			vty_out(vty, "  Outbound Route Filter (ORF):");
			if (CHECK_FLAG(p->af_sflags[afi][safi],
				       PEER_STATUS_ORF_PREFIX_SEND))
				vty_out(vty, " sent;");
			if (orf_pfx_count)
				vty_out(vty, " received (%d entries)",
					orf_pfx_count);
			vty_out(vty, "\n");
		}
		if (CHECK_FLAG(p->af_sflags[afi][safi],
			       PEER_STATUS_ORF_WAIT_REFRESH))
			vty_out(vty,
				"  First update is deferred until ORF or ROUTE-REFRESH is received\n");

		if (CHECK_FLAG(p->af_flags[afi][safi],
			       PEER_FLAG_REFLECTOR_CLIENT))
			vty_out(vty, "  Route-Reflector Client\n");
		if (CHECK_FLAG(p->af_flags[afi][safi],
			       PEER_FLAG_RSERVER_CLIENT))
			vty_out(vty, "  Route-Server Client\n");
		if (CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_SOFT_RECONFIG))
			vty_out(vty,
				"  Inbound soft reconfiguration allowed\n");

		if (CHECK_FLAG(p->af_flags[afi][safi],
			       PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE))
			vty_out(vty,
				"  Private AS numbers (all) replaced in updates to this neighbor\n");
		else if (CHECK_FLAG(p->af_flags[afi][safi],
				    PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE))
			vty_out(vty,
				"  Private AS numbers replaced in updates to this neighbor\n");
		else if (CHECK_FLAG(p->af_flags[afi][safi],
				    PEER_FLAG_REMOVE_PRIVATE_AS_ALL))
			vty_out(vty,
				"  Private AS numbers (all) removed in updates to this neighbor\n");
		else if (CHECK_FLAG(p->af_flags[afi][safi],
				    PEER_FLAG_REMOVE_PRIVATE_AS))
			vty_out(vty,
				"  Private AS numbers removed in updates to this neighbor\n");

		if (CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_ALLOWAS_IN)) {
			if (CHECK_FLAG(p->af_flags[afi][safi],
				       PEER_FLAG_ALLOWAS_IN_ORIGIN))
				vty_out(vty,
					"  Local AS allowed as path origin\n");
			else
				vty_out(vty, "  Local AS allowed in path, %d occurrences\n",
					p->allowas_in[afi][safi]);

			if (p->allowas_in_rmap[afi][safi].name)
				vty_out(vty, "  Local AS allowed with route-map: %s\n",
					p->allowas_in_rmap[afi][safi].name);
		}

		if (p->addpath_type[afi][safi] != BGP_ADDPATH_NONE)
			vty_out(vty, "  %s\n",
				bgp_addpath_names(p->addpath_type[afi][safi])
					->human_description);

		if (CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_AS_OVERRIDE))
			vty_out(vty,
				"  Override ASNs in outbound updates if aspath equals remote-as\n");

		if (CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_NEXTHOP_SELF)
			|| CHECK_FLAG(p->af_flags[afi][safi],
			      PEER_FLAG_FORCE_NEXTHOP_SELF))
			vty_out(vty, "  NEXT_HOP is always this router\n");

		if (CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_FORCE_NEXTHOP_SELF))
			vty_out(vty, "  NEXT_HOP is always this router (force)\n");

		if (CHECK_FLAG(p->af_flags[afi][safi],
			       PEER_FLAG_AS_PATH_UNCHANGED))
			vty_out(vty,
				"  AS_PATH is propagated unchanged to this neighbor\n");
		if (CHECK_FLAG(p->af_flags[afi][safi],
			       PEER_FLAG_NEXTHOP_UNCHANGED))
			vty_out(vty,
				"  NEXT_HOP is propagated unchanged to this neighbor\n");
		if (CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_MED_UNCHANGED))
			vty_out(vty,
				"  MED is propagated unchanged to this neighbor\n");
		if (CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_SEND_COMMUNITY)
		    || CHECK_FLAG(p->af_flags[afi][safi],
				  PEER_FLAG_SEND_EXT_COMMUNITY)
		    || CHECK_FLAG(p->af_flags[afi][safi],
				  PEER_FLAG_SEND_LARGE_COMMUNITY)) {
			vty_out(vty,
				"  Community attribute sent to this neighbor");
			if (CHECK_FLAG(p->af_flags[afi][safi],
				       PEER_FLAG_SEND_COMMUNITY)
			    && CHECK_FLAG(p->af_flags[afi][safi],
					  PEER_FLAG_SEND_EXT_COMMUNITY)
			    && CHECK_FLAG(p->af_flags[afi][safi],
					  PEER_FLAG_SEND_LARGE_COMMUNITY))
				vty_out(vty, "(all)\n");
			else if (CHECK_FLAG(p->af_flags[afi][safi],
					    PEER_FLAG_SEND_LARGE_COMMUNITY))
				vty_out(vty, "(large)\n");
			else if (CHECK_FLAG(p->af_flags[afi][safi],
					    PEER_FLAG_SEND_EXT_COMMUNITY))
				vty_out(vty, "(extended)\n");
			else
				vty_out(vty, "(standard)\n");
		}
		if (CHECK_FLAG(p->af_flags[afi][safi],
			       PEER_FLAG_DEFAULT_ORIGINATE)) {
			vty_out(vty, "  Default information originate,");

			if (p->default_rmap[afi][safi].name)
				vty_out(vty, " default route-map %s%s,",
					p->default_rmap[afi][safi].map ? "*"
								       : "",
					p->default_rmap[afi][safi].name);
			if (paf && PAF_SUBGRP(paf) && PAF_SUBGRP(paf)->default_originate_attr)
				vty_out(vty, " default sent\n");
			else
				vty_out(vty, " default not sent\n");
		}

		/* advertise-vni-all */
		if (afi == AFI_L2VPN && safi == SAFI_EVPN) {
			if (is_evpn_enabled())
				vty_out(vty, "  advertise-all-vni\n");
		}

		if (filter->plist[FILTER_IN].name
		    || filter->dlist[FILTER_IN].name
		    || filter->aslist[FILTER_IN].name
		    || filter->map[RMAP_IN].name)
			vty_out(vty, "  Inbound path policy configured\n");
		if (filter->plist[FILTER_OUT].name
		    || filter->dlist[FILTER_OUT].name
		    || filter->aslist[FILTER_OUT].name
		    || filter->map[RMAP_OUT].name || filter->usmap.name)
			vty_out(vty, "  Outbound path policy configured\n");

		/* prefix-list */
		if (filter->plist[FILTER_IN].name)
			vty_out(vty,
				"  Incoming update prefix filter list is %s%s\n",
				filter->plist[FILTER_IN].plist ? "*" : "",
				filter->plist[FILTER_IN].name);
		if (filter->plist[FILTER_OUT].name)
			vty_out(vty,
				"  Outgoing update prefix filter list is %s%s\n",
				filter->plist[FILTER_OUT].plist ? "*" : "",
				filter->plist[FILTER_OUT].name);

		/* distribute-list */
		if (filter->dlist[FILTER_IN].name)
			vty_out(vty,
				"  Incoming update network filter list is %s%s\n",
				filter->dlist[FILTER_IN].alist ? "*" : "",
				filter->dlist[FILTER_IN].name);
		if (filter->dlist[FILTER_OUT].name)
			vty_out(vty,
				"  Outgoing update network filter list is %s%s\n",
				filter->dlist[FILTER_OUT].alist ? "*" : "",
				filter->dlist[FILTER_OUT].name);

		/* filter-list. */
		if (filter->aslist[FILTER_IN].name)
			vty_out(vty,
				"  Incoming update AS path filter list is %s%s\n",
				filter->aslist[FILTER_IN].aslist ? "*" : "",
				filter->aslist[FILTER_IN].name);
		if (filter->aslist[FILTER_OUT].name)
			vty_out(vty,
				"  Outgoing update AS path filter list is %s%s\n",
				filter->aslist[FILTER_OUT].aslist ? "*" : "",
				filter->aslist[FILTER_OUT].name);

		/* route-map. */
		if (filter->map[RMAP_IN].name)
			vty_out(vty,
				"  Route map for incoming advertisements is %s%s\n",
				filter->map[RMAP_IN].map ? "*" : "",
				filter->map[RMAP_IN].name);
		if (filter->map[RMAP_OUT].name)
			vty_out(vty,
				"  Route map for outgoing advertisements is %s%s\n",
				filter->map[RMAP_OUT].map ? "*" : "",
				filter->map[RMAP_OUT].name);

		/* ebgp-requires-policy (inbound) */
		if (CHECK_FLAG(p->bgp->flags, BGP_FLAG_EBGP_REQUIRES_POLICY)
		    && !bgp_inbound_policy_exists(p, filter))
			vty_out(vty,
				"  Inbound updates discarded due to missing policy\n");

		/* ebgp-requires-policy (outbound) */
		if (CHECK_FLAG(p->bgp->flags, BGP_FLAG_EBGP_REQUIRES_POLICY)
		    && !bgp_outbound_policy_exists(p, filter))
			vty_out(vty,
				"  Outbound updates discarded due to missing policy\n");

		/* unsuppress-map */
		if (filter->usmap.name)
			vty_out(vty,
				"  Route map for selective unsuppress is %s%s\n",
				filter->usmap.map ? "*" : "",
				filter->usmap.name);

		/* advertise-map */
		if (filter->advmap.aname && filter->advmap.cname)
			vty_out(vty,
				"  Condition %s, Condition-map %s%s, Advertise-map %s%s, status: %s\n",
				filter->advmap.condition ? "EXIST"
							 : "NON_EXIST",
				filter->advmap.cmap ? "*" : "",
				filter->advmap.cname,
				filter->advmap.amap ? "*" : "",
				filter->advmap.aname,
				filter->advmap.update_type ==
						UPDATE_TYPE_ADVERTISE
					? "Advertise"
					: "Withdraw");

		/* Receive and sent prefix count, if available */
		paf = peer_af_find(p, afi, safi);
		if (paf && PAF_SUBGRP(paf))
			vty_out(vty, "  %u accepted, %u sent prefixes, %u received duplicates\n",
				p->pcount[afi][pfx_rcd_safi], PAF_SUBGRP(paf)->scount,
				p->pcount_dup[afi][pfx_rcd_safi]);
		else
			vty_out(vty, "  %u accepted prefixes, %u received duplicates\n",
				p->pcount[afi][pfx_rcd_safi], p->pcount_dup[afi][pfx_rcd_safi]);

		/* maximum-prefix-out */
		if (CHECK_FLAG(p->af_flags[afi][safi],
			       PEER_FLAG_MAX_PREFIX_OUT))
			vty_out(vty,
				"  Maximum allowed prefixes sent %u\n",
				p->pmax_out[afi][safi]);

		/* Maximum prefix */
		if (CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_MAX_PREFIX)) {
			vty_out(vty,
				"  Maximum prefixes allowed %u%s\n",
				p->pmax[afi][safi],
				CHECK_FLAG(p->af_flags[afi][safi],
					   PEER_FLAG_MAX_PREFIX_WARNING)
					? " (warning-only)"
					: "");
			vty_out(vty, "  Threshold for warning message %d%%",
				p->pmax_threshold[afi][safi]);
			if (p->pmax_restart[afi][safi])
				vty_out(vty, ", restart interval %d min",
					p->pmax_restart[afi][safi]);
			vty_out(vty, "\n");
		}

		vty_out(vty, "\n");
	}
}

static void bgp_show_peer_status(struct vty *vty, struct peer *p, bool use_json,
				 json_object *json_neigh)
{
	char timebuf[BGP_UPTIME_LEN];

	if (use_json)
		json_object_string_add(json_neigh, "bgpState",
				       lookup_msg(bgp_status_msg, p->connection->status, NULL));
	else
		vty_out(vty, "  BGP state = %s",
			lookup_msg(bgp_status_msg, p->connection->status, NULL));

	if (peer_established(p->connection)) {
		if (use_json) {
			time_t uptime;
			time_t epoch_tbuf;

			uptime = monotime(NULL);
			uptime -= p->uptime;
			epoch_tbuf = time(NULL) - uptime;

			json_object_int_add(json_neigh, "bgpTimerUpMsec", uptime * 1000);
			json_object_string_add(json_neigh, "bgpTimerUpString",
					       peer_uptime(p->uptime, timebuf, BGP_UPTIME_LEN, 0,
							   NULL));
			json_object_int_add(json_neigh, "bgpTimerUpEstablishedEpoch", epoch_tbuf);
		} else
			vty_out(vty, ", up for %8s",
				peer_uptime(p->uptime, timebuf, BGP_UPTIME_LEN, 0, NULL));
	} else if (p->connection->status == Active) {
		if (use_json) {
			if (CHECK_FLAG(p->flags, PEER_FLAG_PASSIVE))
				json_object_string_add(json_neigh, "bgpStateIs", "passive");
			else if (CHECK_FLAG(p->sflags, PEER_STATUS_NSF_WAIT))
				json_object_string_add(json_neigh, "bgpStateIs", "passiveNSF");
		} else {
			if (CHECK_FLAG(p->flags, PEER_FLAG_PASSIVE))
				vty_out(vty, " (passive)");
			else if (CHECK_FLAG(p->sflags, PEER_STATUS_NSF_WAIT))
				vty_out(vty, " (NSF passive)");
		}
	}
	if (!use_json)
		vty_out(vty, "\n");
}

static void bgp_show_peer_gr_capability(struct vty *vty, struct peer *p, bool use_json,
					json_object *json_cap)
{
	if (CHECK_FLAG(p->cap, PEER_CAP_RESTART_RCV) && CHECK_FLAG(p->cap, PEER_CAP_RESTART_ADV)) {
		if (use_json)
			json_object_string_add(json_cap, "gracefulRestart",
					       "advertisedAndReceived");
		else
			vty_out(vty, "    Graceful Restart Capability: advertised and received\n");
	} else if (CHECK_FLAG(p->cap, PEER_CAP_RESTART_ADV)) {
		if (use_json)
			json_object_string_add(json_cap, "gracefulRestart", "advertised");
		else
			vty_out(vty, "    Graceful Restart Capability: advertised\n");
	} else if (CHECK_FLAG(p->cap, PEER_CAP_RESTART_RCV)) {
		if (use_json)
			json_object_string_add(json_cap, "gracefulRestart", "received");
		else
			vty_out(vty, "    Graceful Restart Capability: received\n");
	}

	if (CHECK_FLAG(p->cap, PEER_CAP_RESTART_RCV)) {
		int r_afc = 0;
		afi_t afi;
		safi_t safi;
		json_object *json_restart = NULL;

		if (use_json) {
			json_restart = json_object_new_object();
			json_object_int_add(json_cap, "gracefulRestartRemoteTimerSec",
					    p->v_gr_restart);
		} else
			vty_out(vty, "      Remote Restart timer is %d seconds\n", p->v_gr_restart);

		if (CHECK_FLAG(p->cap, PEER_CAP_GRACEFUL_RESTART_R_BIT_RCV)) {
			if (use_json)
				json_object_boolean_true_add(json_cap, "rBitReceived");
			else
				vty_out(vty, "      Peer has restarted (R-bit is set)\n");
		}

		if (CHECK_FLAG(p->cap, PEER_CAP_GRACEFUL_RESTART_N_BIT_RCV)) {
			if (use_json)
				json_object_boolean_true_add(json_cap, "nBitReceived");
			else
				vty_out(vty, "      Peer has restarted (N-bit is set)\n");
		}

		if (!use_json)
			vty_out(vty, "      Address families by peer:\n        ");

		FOREACH_AFI_SAFI (afi, safi) {
			if (CHECK_FLAG(p->af_cap[afi][safi], PEER_CAP_RESTART_AF_RCV)) {
				bool f_bit;

				f_bit = CHECK_FLAG(p->af_cap[afi][safi],
						   PEER_CAP_RESTART_AF_PRESERVE_RCV);

				if (use_json) {
					json_object *json_sub = NULL;

					json_sub = json_object_new_object();
					if (f_bit)
						json_object_boolean_true_add(json_sub, "preserved");
					json_object_object_add(json_restart,
							       get_afi_safi_str(afi, safi, true),
							       json_sub);
				} else {
					vty_out(vty, "%s%s(%s)", r_afc ? ", " : "",
						get_afi_safi_str(afi, safi, false),
						f_bit ? "preserved" : "not preserved");
				}
				r_afc++;
			}
		}
		if (!r_afc) {
			if (use_json) {
				json_object_string_add(json_cap, "addressFamiliesByPeer", "none");
				json_object_free(json_restart);
			} else
				vty_out(vty, "none\n");
		} else {
			if (use_json)
				json_object_object_add(json_cap, "addressFamiliesByPeer",
						       json_restart);
			else
				vty_out(vty, "\n");
		}
	}
}

static void bgp_show_peer_gr_extra_info(struct vty *vty, struct peer *p, bool use_json,
					json_object *json_neigh)
{
	json_object *json_grace = NULL;
	json_object *json_grace_send = NULL;
	json_object *json_grace_recv = NULL;
	int eor_send_af_count = 0;
	int eor_receive_af_count = 0;
	afi_t afi;
	safi_t safi;

	if (use_json) {
		json_grace = json_object_new_object();
		json_grace_send = json_object_new_object();
		json_grace_recv = json_object_new_object();

		if (peer_established(p->connection) && CHECK_FLAG(p->cap, PEER_CAP_RESTART_RCV)) {
			FOREACH_AFI_SAFI (afi, safi) {
				if (CHECK_FLAG(p->af_sflags[afi][safi], PEER_STATUS_EOR_SEND)) {
					json_object_boolean_true_add(json_grace_send,
								     get_afi_safi_str(afi, safi,
										      true));
					eor_send_af_count++;
				}

				if (CHECK_FLAG(p->af_sflags[afi][safi], PEER_STATUS_EOR_RECEIVED)) {
					json_object_boolean_true_add(json_grace_recv,
								     get_afi_safi_str(afi, safi,
										      true));
					eor_receive_af_count++;
				}
			}
		}
		json_object_object_add(json_grace, "endOfRibSend", json_grace_send);
		json_object_object_add(json_grace, "endOfRibRecv", json_grace_recv);


		if (event_is_scheduled(p->connection->t_gr_restart))
			json_object_int_add(json_grace, "gracefulRestartTimerSec",
					    event_timer_remain_second(p->connection->t_gr_restart));

		if (event_is_scheduled(p->connection->t_gr_stale))
			json_object_int_add(json_grace, "gracefulStalepathTimerSec",
					    event_timer_remain_second(p->connection->t_gr_stale));
		/* more gr info in new format */
		BGP_SHOW_PEER_GR_CAPABILITY(vty, p, json_grace);
		json_object_object_add(json_neigh, "gracefulRestartInfo", json_grace);
	} else {
		vty_out(vty, "  Graceful restart information:\n");
		if (peer_established(p->connection) && CHECK_FLAG(p->cap, PEER_CAP_RESTART_RCV)) {
			vty_out(vty, "    End-of-RIB send: ");
			FOREACH_AFI_SAFI (afi, safi) {
				if (CHECK_FLAG(p->af_sflags[afi][safi], PEER_STATUS_EOR_SEND)) {
					vty_out(vty, "%s%s", eor_send_af_count ? ", " : "",
						get_afi_safi_str(afi, safi, false));
					eor_send_af_count++;
				}
			}
			vty_out(vty, "\n");
			vty_out(vty, "    End-of-RIB received: ");
			FOREACH_AFI_SAFI (afi, safi) {
				if (CHECK_FLAG(p->af_sflags[afi][safi], PEER_STATUS_EOR_RECEIVED)) {
					vty_out(vty, "%s%s", eor_receive_af_count ? ", " : "",
						get_afi_safi_str(afi, safi, false));
					eor_receive_af_count++;
				}
			}
			vty_out(vty, "\n");
		}

		if (event_is_scheduled(p->connection->t_gr_restart))
			vty_out(vty, "    The remaining time of restart timer is %ld\n",
				event_timer_remain_second(p->connection->t_gr_restart));

		if (event_is_scheduled(p->connection->t_gr_stale))
			vty_out(vty, "    The remaining time of stalepath timer is %ld\n",
				event_timer_remain_second(p->connection->t_gr_stale));

		/* more gr info in new format */
		BGP_SHOW_PEER_GR_CAPABILITY(vty, p, NULL);
	}
}

static void bgp_show_peer_gr_info(struct vty *vty, struct peer *p, bool use_json,
				  json_object *json_neigh)
{
	json_object *json_cap = NULL;

	if (use_json) {
		/* Administrative shutdown. */
		if (CHECK_FLAG(p->flags, PEER_FLAG_SHUTDOWN))
			json_object_boolean_true_add(json_neigh, "adminShutDown");
	} else {
		/* Administrative shutdown. */
		if (CHECK_FLAG(p->flags, PEER_FLAG_SHUTDOWN))
			vty_out(vty, " Administratively shut down\n");
	}

	/* Status. */
	bgp_show_peer_status(vty, p, use_json, json_neigh);

	/* GR capability info */
	if (use_json)
		json_cap = json_object_new_object();
	else
		vty_out(vty, "  Neighbor GR capabilities:\n");
	bgp_show_peer_gr_capability(vty, p, use_json, json_cap);
	if (use_json)
		json_object_object_add(json_neigh, "neighborCapabilities", json_cap);

	/* more gr info */
	bgp_show_peer_gr_extra_info(vty, p, use_json, json_neigh);
}

static void bgp_show_peer(struct vty *vty, struct peer *p, uint16_t sh_flags, bool use_json,
			  json_object *json)
{
	struct bgp *bgp;
	char buf[PREFIX2STR_BUFFER];
	char timebuf[BGP_UPTIME_LEN];
	char dn_flag[2] = {};
	afi_t afi;
	safi_t safi;
	uint16_t i;
	int len = 0;
	uint8_t *msg;
	json_object *json_neigh = NULL, *json_stat = NULL, *json_addr_family_info = NULL;
	uint32_t sync_tcp_mss;
	int neighbor_col_default_width = 16;
	struct peer_af *paf;
	const char *afi_safi = NULL;
	uint32_t peer_pcount = 0, peer_scount = 0;
	bool is_first_afi_safi = true;
	bool show_brief = ((CHECK_FLAG(sh_flags, VTY_BGP_PEER_SHOW_STATE_ESTABLISHED_INFO) ||
			    CHECK_FLAG(sh_flags, VTY_BGP_PEER_SHOW_STATE_FAILED_INFO) ||
			    CHECK_FLAG(sh_flags, VTY_BGP_PEER_SHOW_BRIEF_INFO)));
	bool enhe_enabled = false;
	bool enforce_first_as = false;

	bgp = p->bgp;

	if (use_json)
		json_neigh = json_object_new_object();

	if (!p->conf_if && peer_dynamic_neighbor(p))
		dn_flag[0] = '*';

	if (show_brief) {
		if (use_json) {
			time_t uptime;

			if (p->hostname)
				json_object_string_add(json_neigh, "hostname", p->hostname);
			else
				json_object_string_add(json_neigh, "hostname", "Unknown");
			asn_asn2json(json_neigh, "remoteAs", p->as, bgp->asnotation);
			if (p->change_local_as)
				asn_asn2json(json_neigh, "localAs", p->change_local_as,
					     bgp->asnotation);
			else
				asn_asn2json(json_neigh, "localAs", p->local_as, bgp->asnotation);
			json_object_string_add(json_neigh, "lastResetDueTo",
					       peer_down_str[(int)p->last_reset]);
			bgp_show_peer_status(vty, p, use_json, json_neigh);

			uptime = monotime(NULL);
			uptime -= p->resettime;

			json_object_int_add(json_neigh, "lastResetTimerMsecs",
					    (int64_t)uptime * 1000);
			json_stat = json_object_new_object();
			json_object_int_add(json_stat, "totalSent", PEER_TOTAL_TX(p));
			json_object_int_add(json_stat, "totalRecv", PEER_TOTAL_RX(p));
			json_object_object_add(json_neigh, "messageStats", json_stat);
			json_addr_family_info = json_object_new_object();
			json_object_object_add(json_neigh, "addressFamilyInfo",
					       json_addr_family_info);
			if (p->conf_if)
				json_object_object_add(json, p->conf_if, json_neigh);
			else
				json_object_object_add(json, p->host, json_neigh);
		} else {
			if (p->hostname && CHECK_FLAG(bgp->flags, BGP_FLAG_SHOW_HOSTNAME))
				len = vty_out(vty, "%s%s(%s)", dn_flag, p->hostname, p->host);
			else
				len = vty_out(vty, "%s%s", dn_flag, p->host);
			if (len < neighbor_col_default_width)
				vty_out(vty, "%*s", neighbor_col_default_width - len, " ");
			vty_out(vty, "%10u %9u %9u %10s %12s ", p->as, PEER_TOTAL_RX(p),
				PEER_TOTAL_TX(p),
				peer_uptime(p->resettime, timebuf, BGP_UPTIME_LEN, 0, NULL),
				lookup_msg(bgp_status_msg, p->connection->status, NULL));
		}
		FOREACH_AFI_SAFI (afi, safi) {
			if (p->afc[afi][safi]) {
				paf = peer_af_find(p, afi, safi);
				peer_pcount = p->pcount[afi][safi];
				peer_scount = ((paf && PAF_SUBGRP(paf)) ? PAF_SUBGRP(paf)->scount
									: 0);
				if (!use_json) {
					afi_safi = get_afi_safi_str(afi, safi, false);
					if (is_first_afi_safi) {
						vty_out(vty, "%16s %9u %9u\n", afi_safi,
							peer_pcount, peer_scount);
						is_first_afi_safi = false;
					} else
						vty_out(vty, "%70s %16s %9u %9u\n", " ", afi_safi,
							peer_pcount, peer_scount);
				} else {
					afi_safi = get_afi_safi_str(afi, safi, true);
					json_object *json_addr = json_object_new_object();
					json_object_int_add(json_addr, "acceptedPrefixCounter",
							    peer_pcount);
					json_object_int_add(json_addr, "sentPrefixCounter",
							    peer_scount);
					json_object_object_add(json_addr_family_info, afi_safi,
							       json_addr);
				}
			}
		}
		return;
	}

	if (peergroup_flag_check(p, PEER_FLAG_CAPABILITY_ENHE))
		enhe_enabled = !(CHECK_FLAG(p->flags_invert, PEER_FLAG_CAPABILITY_ENHE) &&
				 !p->conf_if);

	enforce_first_as = CHECK_FLAG(bgp->flags, BGP_FLAG_ENFORCE_FIRST_AS);
	if (peergroup_flag_check(p, PEER_FLAG_ENFORCE_FIRST_AS))
		enforce_first_as = !enforce_first_as;

	if (use_json) {
		if (p->conf_if && BGP_CONNECTION_SU_UNSPEC(p->connection))
			json_object_string_add(json_neigh, "bgpNeighborAddr", "none");
		else if (p->conf_if && !BGP_CONNECTION_SU_UNSPEC(p->connection))
			json_object_string_add(json_neigh, "bgpNeighborAddr",
					       sockunion2str(&p->connection->su, buf,
							     SU_ADDRSTRLEN));

		/* passive */
		json_object_boolean_add(json_neigh, "passive",
			peergroup_flag_check(p, PEER_FLAG_PASSIVE));

		/* disable-connected-check */
		json_object_boolean_add(json_neigh, "disableConnectedCheck",
			peergroup_flag_check(p, PEER_FLAG_DISABLE_CONNECTED_CHECK));

		/* graceful-shutdown */
		json_object_boolean_add(json_neigh, "gracefulShutdown",
			peergroup_flag_check(p, PEER_FLAG_GRACEFUL_SHUTDOWN));

		/* enforce-first-as */
		json_object_boolean_add(json_neigh, "enforceFirstAs", enforce_first_as);

		/* capability extended-nexthop */
		json_object_boolean_add(json_neigh, "capabilityExtendedNexthop", enhe_enabled);

		if (p->conf_if)
			json_object_string_addf(json_neigh, "neighborAddr", "%pSU",
						&p->connection->su);
		else {
			char neighborAddr[INET6_ADDRSTRLEN + 1] = { 0 };

			snprintf(neighborAddr, sizeof(neighborAddr), "%s%s", dn_flag, p->host);

			json_object_string_add(json_neigh, "neighborAddr", neighborAddr);
		}
	} else {
		if (p->conf_if) /* Configured interface name. */
			vty_out(vty, "BGP neighbor on %s: %pSU, ", p->conf_if,
				&p->connection->su);
		else /* Configured IP address. */
			vty_out(vty, "BGP neighbor is %s%s, ", dn_flag,
				p->host);

		/* passive */
		if (peergroup_flag_check(p, PEER_FLAG_PASSIVE))
			vty_out(vty, "passive, ");

		/* disable-connected-check */
		if (peergroup_flag_check(p, PEER_FLAG_DISABLE_CONNECTED_CHECK))
			vty_out(vty, "disable connected check, ");

		/* graceful-shutdown */
		if (peergroup_flag_check(p, PEER_FLAG_GRACEFUL_SHUTDOWN))
			vty_out(vty, "graceful shutdown, ");

		/* enforce-first-as */
		if (!enforce_first_as)
			vty_out(vty, "no enforce first as, ");

		/* capability extended-nexthop */
		if (enhe_enabled)
			vty_out(vty, "capability extended nexthop, ");
	}

	if (use_json) {
		if (p->conf_if && BGP_CONNECTION_SU_UNSPEC(p->connection))
			json_object_string_add(json_neigh, "bgpNeighborAddr",
					       "none");
		else if (p->conf_if && !BGP_CONNECTION_SU_UNSPEC(p->connection))
			json_object_string_addf(json_neigh, "bgpNeighborAddr",
						"%pSU", &p->connection->su);

		asn_asn2json(json_neigh, "remoteAs", p->as, bgp->asnotation);

		if (p->change_local_as)
			asn_asn2json(json_neigh, "localAs", p->change_local_as,
				     bgp->asnotation);
		else
			asn_asn2json(json_neigh, "localAs", p->local_as,
				     bgp->asnotation);

		if (CHECK_FLAG(p->flags, PEER_FLAG_LOCAL_AS_NO_PREPEND))
			json_object_boolean_true_add(json_neigh,
						     "localAsNoPrepend");

		if (CHECK_FLAG(p->flags, PEER_FLAG_LOCAL_AS_REPLACE_AS))
			json_object_boolean_true_add(json_neigh,
						     "localAsReplaceAs");

		json_object_boolean_add(json_neigh, "localAsReplaceAsDualAs",
					!!CHECK_FLAG(p->flags,
						     PEER_FLAG_DUAL_AS));
	} else {
		if (p->as_type == AS_SPECIFIED ||
		    CHECK_FLAG(p->as_type, AS_AUTO) ||
		    CHECK_FLAG(p->as_type, AS_EXTERNAL) ||
		    CHECK_FLAG(p->as_type, AS_INTERNAL)) {
			vty_out(vty, "remote AS ");
			vty_out(vty, ASN_FORMAT(bgp->asnotation), &p->as);
			vty_out(vty, ", ");
		} else
			vty_out(vty, "remote AS Unspecified, ");
		vty_out(vty, "local AS ");
		vty_out(vty, ASN_FORMAT(bgp->asnotation),
			p->change_local_as ? &p->change_local_as
					   : &p->local_as);
		vty_out(vty, "%s%s%s, ",
			CHECK_FLAG(p->flags, PEER_FLAG_LOCAL_AS_NO_PREPEND)
				? " no-prepend"
				: "",
			CHECK_FLAG(p->flags, PEER_FLAG_LOCAL_AS_REPLACE_AS)
				? " replace-as"
				: "",
			CHECK_FLAG(p->flags, PEER_FLAG_DUAL_AS) ? " dual-as"
								: "");
	}
	/* peer type internal or confed-internal */
	if (p->as == p->local_as || (p->change_local_as && p->as == p->change_local_as) ||
	    CHECK_FLAG(p->as_type, AS_INTERNAL)) {
		if (use_json) {
			if (CHECK_FLAG(bgp->config, BGP_CONFIG_CONFEDERATION))
				json_object_boolean_true_add(
					json_neigh, "nbrConfedInternalLink");
			else
				json_object_boolean_true_add(json_neigh,
							     "nbrInternalLink");
		} else {
			if (CHECK_FLAG(bgp->config, BGP_CONFIG_CONFEDERATION))
				vty_out(vty, "confed-internal link\n");
			else
				vty_out(vty, "internal link\n");
		}
	/* peer type external or confed-external */
	} else if (p->as || CHECK_FLAG(p->as_type, AS_EXTERNAL)) {
		if (use_json) {
			if (CHECK_FLAG(bgp->config, BGP_CONFIG_CONFEDERATION))
				json_object_boolean_true_add(
					json_neigh, "nbrConfedExternalLink");
			else
				json_object_boolean_true_add(json_neigh,
							     "nbrExternalLink");
		} else {
			if (bgp_confederation_peers_check(bgp, p->as))
				vty_out(vty, "confed-external link\n");
			else
				vty_out(vty, "external link\n");
		}
	} else {
		if (use_json)
			json_object_boolean_true_add(json_neigh,
						     "nbrUnspecifiedLink");
		else
			vty_out(vty, "unspecified link\n");
	}

	/* Roles */
	if (use_json) {
		json_object_string_add(json_neigh, "localRole", bgp_get_local_role_name(p));
		json_object_string_add(json_neigh, "remoteRole", bgp_get_remote_role_name(p));
	} else {
		vty_out(vty, "  Local Role: %s\n", bgp_get_local_role_name(p));
		vty_out(vty, "  Remote Role: %s\n", bgp_get_remote_role_name(p));
	}

	/* Are we showing specific information? */
	if (sh_flags) {
		if (sh_flags & VTY_BGP_PEER_SHOW_GR_INFO)
			bgp_show_peer_gr_info(vty, p, use_json, json_neigh);

		/* Finish JSON, if needed. */
		if (use_json) {
			if (p->conf_if) /* Configured interface name. */
				json_object_object_add(json, p->conf_if, json_neigh);
			else /* Configured IP address. */
				json_object_object_add(json, p->host, json_neigh);
		}

		return;
	}

	/* Description. */
	if (p->desc) {
		if (use_json)
			json_object_string_add(json_neigh, "nbrDesc", p->desc);
		else
			vty_out(vty, " Description: %s\n", p->desc);
	}

	if (p->hostname) {
		if (use_json) {
			json_object_string_add(json_neigh, "hostname",
					       p->hostname);

			if (p->domainname)
				json_object_string_add(json_neigh, "domainname",
						       p->domainname);
		} else {
			if (p->domainname && (p->domainname[0] != '\0'))
				vty_out(vty, "Hostname: %s.%s\n", p->hostname,
					p->domainname);
			else
				vty_out(vty, "Hostname: %s\n", p->hostname);
		}
	} else {
		if (use_json)
			json_object_string_add(json_neigh, "hostname",
					       "Unknown");
	}

	/* Peer-group */
	if (p->group) {
		if (use_json) {
			json_object_string_add(json_neigh, "peerGroup",
					       p->group->name);

			if (dn_flag[0]) {
				struct prefix prefix, *range = NULL;

				if (sockunion2hostprefix(&p->connection->su,
							 &prefix))
					range = peer_group_lookup_dynamic_neighbor_range(
						p->group, &prefix);

				if (range) {
					json_object_string_addf(
						json_neigh,
						"peerSubnetRangeGroup", "%pFX",
						range);
				}
			}
		} else {
			vty_out(vty,
				" Member of peer-group %s for session parameters\n",
				p->group->name);

			if (dn_flag[0]) {
				struct prefix prefix, *range = NULL;

				if (sockunion2hostprefix(&p->connection->su,
							 &prefix))
					range = peer_group_lookup_dynamic_neighbor_range(
						p->group, &prefix);

				if (range) {
					vty_out(vty,
						" Belongs to the subnet range group: %pFX\n",
						range);
				}
			}
		}
	}

	if (use_json) {
		/* Administrative shutdown. */
		if (CHECK_FLAG(p->flags, PEER_FLAG_SHUTDOWN)
		    || CHECK_FLAG(p->bgp->flags, BGP_FLAG_SHUTDOWN))
			json_object_boolean_true_add(json_neigh,
						     "adminShutDown");

		/* BGP Version. */
		json_object_int_add(json_neigh, "bgpVersion", 4);
		json_object_string_addf(json_neigh, "remoteRouterId", "%pI4",
					&p->remote_id);
		json_object_string_addf(json_neigh, "localRouterId", "%pI4",
					&bgp->router_id);

		/* Confederation */
		if (CHECK_FLAG(bgp->config, BGP_CONFIG_CONFEDERATION)
		    && bgp_confederation_peers_check(bgp, p->as))
			json_object_boolean_true_add(json_neigh,
						     "nbrCommonAdmin");

		/* Status. */
		bgp_show_peer_status(vty, p, use_json, json_neigh);

		/* read timer */
		time_t uptime;

		uptime = monotime(NULL);
		uptime -= p->readtime;

		json_object_int_add(json_neigh, "bgpTimerLastRead",
				    (int64_t)uptime * 1000);

		uptime = monotime(NULL);
		uptime -= p->last_write;

		json_object_int_add(json_neigh, "bgpTimerLastWrite",
				    (int64_t)uptime * 1000);

		uptime = monotime(NULL);
		uptime -= p->update_time;

		json_object_int_add(json_neigh, "bgpInUpdateElapsedTimeMsecs",
				    (int64_t)uptime * 1000);

		/* Configured timer values. */
		json_object_int_add(json_neigh,
				    "bgpTimerConfiguredHoldTimeMsecs",
				    CHECK_FLAG(p->flags, PEER_FLAG_TIMER)
					    ? p->holdtime * 1000
					    : bgp->default_holdtime * 1000);
		json_object_int_add(json_neigh,
				    "bgpTimerConfiguredKeepAliveIntervalMsecs",
				    CHECK_FLAG(p->flags, PEER_FLAG_TIMER)
					    ? p->keepalive * 1000
					    : bgp->default_keepalive * 1000);
		json_object_int_add(json_neigh, "bgpTimerHoldTimeMsecs",
				    p->v_holdtime * 1000);
		json_object_int_add(json_neigh,
				    "bgpTimerKeepAliveIntervalMsecs",
				    p->v_keepalive * 1000);
		if (CHECK_FLAG(p->flags, PEER_FLAG_TIMER_DELAYOPEN)) {
			json_object_int_add(json_neigh,
					    "bgpTimerDelayOpenTimeMsecs",
					    p->v_delayopen * 1000);
		}

		/* Configured and Synced tcp-mss value for peer */
		sync_tcp_mss = sockopt_tcp_mss_get(p->connection->fd);
		json_object_int_add(json_neigh, "bgpTcpMssConfigured",
				    p->tcp_mss);
		json_object_int_add(json_neigh, "bgpTcpMssSynced", sync_tcp_mss);

		/* Extended Optional Parameters Length for BGP OPEN Message */
		if (BGP_OPEN_EXT_OPT_PARAMS_CAPABLE(p))
			json_object_boolean_true_add(
				json_neigh, "extendedOptionalParametersLength");
		else
			json_object_boolean_false_add(
				json_neigh, "extendedOptionalParametersLength");

		/* Conditional advertisements */
		json_object_int_add(
			json_neigh,
			"bgpTimerConfiguredConditionalAdvertisementsSec",
			bgp->condition_check_period);
		if (event_is_scheduled(bgp->t_condition_check))
			json_object_int_add(
				json_neigh,
				"bgpTimerUntilConditionalAdvertisementsSec",
				event_timer_remain_second(
					bgp->t_condition_check));
	} else {
		/* Administrative shutdown. */
		if (CHECK_FLAG(p->flags, PEER_FLAG_SHUTDOWN)
		    || CHECK_FLAG(p->bgp->flags, BGP_FLAG_SHUTDOWN))
			vty_out(vty, " Administratively shut down\n");

		/* BGP Version. */
		vty_out(vty, "  BGP version 4");
		vty_out(vty, ", remote router ID %pI4", &p->remote_id);
		vty_out(vty, ", local router ID %pI4\n", &bgp->router_id);

		/* Confederation */
		if (CHECK_FLAG(bgp->config, BGP_CONFIG_CONFEDERATION)
		    && bgp_confederation_peers_check(bgp, p->as))
			vty_out(vty,
				"  Neighbor under common administration\n");

		/* Status. */
		bgp_show_peer_status(vty, p, use_json, json_neigh);

		/* read timer */
		vty_out(vty, "  Last read %s",
			peer_uptime(p->readtime, timebuf, BGP_UPTIME_LEN, 0,
				    NULL));
		vty_out(vty, ", Last write %s\n",
			peer_uptime(p->last_write, timebuf, BGP_UPTIME_LEN, 0,
				    NULL));

		/* Configured timer values. */
		vty_out(vty,
			"  Hold time is %d seconds, keepalive interval is %d seconds\n",
			p->v_holdtime, p->v_keepalive);
		vty_out(vty, "  Configured hold time is %d seconds",
			CHECK_FLAG(p->flags, PEER_FLAG_TIMER)
				? p->holdtime
				: bgp->default_holdtime);
		vty_out(vty, ", keepalive interval is %d seconds\n",
			CHECK_FLAG(p->flags, PEER_FLAG_TIMER)
				? p->keepalive
				: bgp->default_keepalive);
		if (CHECK_FLAG(p->flags, PEER_FLAG_TIMER_DELAYOPEN))
			vty_out(vty,
				"  Configured DelayOpenTime is %d seconds\n",
				p->delayopen);

		/* Configured and synced tcp-mss value for peer */
		sync_tcp_mss = sockopt_tcp_mss_get(p->connection->fd);
		vty_out(vty, "  Configured tcp-mss is %d", p->tcp_mss);
		vty_out(vty, ", synced tcp-mss is %d\n", sync_tcp_mss);

		/* Extended Optional Parameters Length for BGP OPEN Message */
		if (BGP_OPEN_EXT_OPT_PARAMS_CAPABLE(p))
			vty_out(vty,
				"  Extended Optional Parameters Length is enabled\n");

		/* Conditional advertisements */
		vty_out(vty,
			"  Configured conditional advertisements interval is %d seconds\n",
			bgp->condition_check_period);
		if (event_is_scheduled(bgp->t_condition_check))
			vty_out(vty,
				"  Time until conditional advertisements begin is %lu seconds\n",
				event_timer_remain_second(
					bgp->t_condition_check));
	}
	/* Capability. */
	if (peer_established(p->connection) &&
	    (p->cap || peer_afc_advertised(p) || peer_afc_received(p))) {
		if (use_json) {
			json_object *json_cap = NULL;

			json_cap = json_object_new_object();

			/* AS4 */
			if (CHECK_FLAG(p->cap, PEER_CAP_AS4_RCV) ||
			    CHECK_FLAG(p->cap, PEER_CAP_AS4_ADV)) {
				if (CHECK_FLAG(p->cap, PEER_CAP_AS4_ADV) &&
				    CHECK_FLAG(p->cap, PEER_CAP_AS4_RCV))
					json_object_string_add(
						json_cap, "4byteAs",
						"advertisedAndReceived");
				else if (CHECK_FLAG(p->cap, PEER_CAP_AS4_ADV))
					json_object_string_add(json_cap,
							       "4byteAs",
							       "advertised");
				else if (CHECK_FLAG(p->cap, PEER_CAP_AS4_RCV))
					json_object_string_add(json_cap,
							       "4byteAs",
							       "received");
			}

			/* Extended Message Support */
			if (CHECK_FLAG(p->cap, PEER_CAP_EXTENDED_MESSAGE_ADV) &&
			    CHECK_FLAG(p->cap, PEER_CAP_EXTENDED_MESSAGE_RCV))
				json_object_string_add(json_cap,
						       "extendedMessage",
						       "advertisedAndReceived");
			else if (CHECK_FLAG(p->cap,
					    PEER_CAP_EXTENDED_MESSAGE_ADV))
				json_object_string_add(json_cap,
						       "extendedMessage",
						       "advertised");
			else if (CHECK_FLAG(p->cap,
					    PEER_CAP_EXTENDED_MESSAGE_RCV))
				json_object_string_add(json_cap,
						       "extendedMessage",
						       "received");

			/* AddPath */
			if (CHECK_FLAG(p->cap, PEER_CAP_ADDPATH_RCV) ||
			    CHECK_FLAG(p->cap, PEER_CAP_ADDPATH_ADV)) {
				json_object *json_add = NULL;
				const char *print_store;

				json_add = json_object_new_object();

				FOREACH_AFI_SAFI (afi, safi) {
					json_object *json_sub = NULL;

					json_sub = json_object_new_object();
					print_store = get_afi_safi_str(
						afi, safi, true);

					if (CHECK_FLAG(
						    p->af_cap[afi][safi],
						    PEER_CAP_ADDPATH_AF_TX_ADV) ||
					    CHECK_FLAG(
						    p->af_cap[afi][safi],
						    PEER_CAP_ADDPATH_AF_TX_RCV)) {
						json_object_boolean_add(
							json_sub,
							"txAdvertisedAndReceived",
							CHECK_FLAG(p->af_cap[afi]
									    [safi],
								   PEER_CAP_ADDPATH_AF_TX_ADV) &&
								CHECK_FLAG(
									p->af_cap[afi]
										 [safi],
									PEER_CAP_ADDPATH_AF_TX_RCV));

						json_object_boolean_add(
							json_sub, "txAdvertised",
							CHECK_FLAG(p->af_cap[afi]
									    [safi],
								   PEER_CAP_ADDPATH_AF_TX_ADV));

						json_object_boolean_add(
							json_sub, "txReceived",
							CHECK_FLAG(p->af_cap[afi]
									    [safi],
								   PEER_CAP_ADDPATH_AF_TX_RCV));
					}

					if (CHECK_FLAG(
						    p->af_cap[afi][safi],
						    PEER_CAP_ADDPATH_AF_RX_ADV) ||
					    CHECK_FLAG(
						    p->af_cap[afi][safi],
						    PEER_CAP_ADDPATH_AF_RX_RCV)) {
						json_object_boolean_add(
							json_sub,
							"rxAdvertisedAndReceived",
							CHECK_FLAG(p->af_cap[afi]
									    [safi],
								   PEER_CAP_ADDPATH_AF_RX_ADV) &&
								CHECK_FLAG(
									p->af_cap[afi]
										 [safi],
									PEER_CAP_ADDPATH_AF_RX_RCV));

						json_object_boolean_add(
							json_sub, "rxAdvertised",
							CHECK_FLAG(p->af_cap[afi]
									    [safi],
								   PEER_CAP_ADDPATH_AF_RX_ADV));

						json_object_boolean_add(
							json_sub, "rxReceived",
							CHECK_FLAG(p->af_cap[afi]
									    [safi],
								   PEER_CAP_ADDPATH_AF_RX_RCV));
					}

					if (CHECK_FLAG(
						    p->af_cap[afi][safi],
						    PEER_CAP_ADDPATH_AF_TX_ADV) ||
					    CHECK_FLAG(
						    p->af_cap[afi][safi],
						    PEER_CAP_ADDPATH_AF_TX_RCV) ||
					    CHECK_FLAG(
						    p->af_cap[afi][safi],
						    PEER_CAP_ADDPATH_AF_RX_ADV) ||
					    CHECK_FLAG(
						    p->af_cap[afi][safi],
						    PEER_CAP_ADDPATH_AF_RX_RCV))
						json_object_object_add(
							json_add, print_store,
							json_sub);
					else
						json_object_free(json_sub);
				}

				json_object_object_add(json_cap, "addPath",
						       json_add);
			}

			/* Paths-Limit */
			if (CHECK_FLAG(p->cap, PEER_CAP_PATHS_LIMIT_RCV) ||
			    CHECK_FLAG(p->cap, PEER_CAP_PATHS_LIMIT_ADV)) {
				json_object *json_add = NULL;
				const char *print_store;

				json_add = json_object_new_object();

				FOREACH_AFI_SAFI (afi, safi) {
					json_object *json_sub = NULL;

					json_sub = json_object_new_object();
					print_store = get_afi_safi_str(afi, safi,
								       true);

					if (CHECK_FLAG(p->af_cap[afi][safi],
						       PEER_CAP_PATHS_LIMIT_AF_ADV) ||
					    CHECK_FLAG(p->af_cap[afi][safi],
						       PEER_CAP_PATHS_LIMIT_AF_RCV)) {
						if (CHECK_FLAG(p->af_cap[afi][safi],
							       PEER_CAP_PATHS_LIMIT_AF_ADV) &&
						    CHECK_FLAG(p->af_cap[afi][safi],
							       PEER_CAP_PATHS_LIMIT_AF_RCV)) {
							json_object_boolean_true_add(
								json_sub,
								"advertisedAndReceived");
							json_object_int_add(
								json_sub,
								"advertisedPathsLimit",
								p->addpath_paths_limit
									[afi][safi]
										.send);
							json_object_int_add(
								json_sub,
								"receivedPathsLimit",
								p->addpath_paths_limit
									[afi][safi]
										.receive);
						} else if (CHECK_FLAG(p->af_cap[afi]
									       [safi],
								      PEER_CAP_PATHS_LIMIT_AF_ADV)) {
							json_object_boolean_true_add(
								json_sub,
								"advertised");
							json_object_int_add(
								json_sub,
								"advertisedPathsLimit",
								p->addpath_paths_limit
									[afi][safi]
										.send);
						} else if (CHECK_FLAG(p->af_cap[afi]
									       [safi],
								      PEER_CAP_PATHS_LIMIT_AF_RCV)) {
							json_object_boolean_true_add(
								json_sub,
								"received");
							json_object_int_add(
								json_sub,
								"receivedPathsLimit",
								p->addpath_paths_limit
									[afi][safi]
										.receive);
						}
					}

					if (CHECK_FLAG(p->af_cap[afi][safi],
						       PEER_CAP_PATHS_LIMIT_AF_ADV) ||
					    CHECK_FLAG(p->af_cap[afi][safi],
						       PEER_CAP_PATHS_LIMIT_AF_RCV))
						json_object_object_add(json_add,
								       print_store,
								       json_sub);
					else
						json_object_free(json_sub);
				}

				json_object_object_add(json_cap, "pathsLimit",
						       json_add);
			}

			/* Dynamic */
			if (CHECK_FLAG(p->cap, PEER_CAP_DYNAMIC_RCV) ||
			    CHECK_FLAG(p->cap, PEER_CAP_DYNAMIC_ADV)) {
				if (CHECK_FLAG(p->cap, PEER_CAP_DYNAMIC_ADV) &&
				    CHECK_FLAG(p->cap, PEER_CAP_DYNAMIC_RCV))
					json_object_string_add(
						json_cap, "dynamic",
						"advertisedAndReceived");
				else if (CHECK_FLAG(p->cap,
						    PEER_CAP_DYNAMIC_ADV))
					json_object_string_add(json_cap,
							       "dynamic",
							       "advertised");
				else if (CHECK_FLAG(p->cap,
						    PEER_CAP_DYNAMIC_RCV))
					json_object_string_add(json_cap,
							       "dynamic",
							       "received");
			}

			/* Role */
			if (CHECK_FLAG(p->cap, PEER_CAP_ROLE_RCV) ||
			    CHECK_FLAG(p->cap, PEER_CAP_ROLE_ADV)) {
				if (CHECK_FLAG(p->cap, PEER_CAP_ROLE_ADV) &&
				    CHECK_FLAG(p->cap, PEER_CAP_ROLE_RCV))
					json_object_string_add(
						json_cap, "role",
						"advertisedAndReceived");
				else if (CHECK_FLAG(p->cap, PEER_CAP_ROLE_ADV))
					json_object_string_add(json_cap, "role",
							       "advertised");
				else if (CHECK_FLAG(p->cap, PEER_CAP_ROLE_RCV))
					json_object_string_add(json_cap, "role",
							       "received");
			}

			/* Extended nexthop */
			if (CHECK_FLAG(p->cap, PEER_CAP_ENHE_RCV) ||
			    CHECK_FLAG(p->cap, PEER_CAP_ENHE_ADV)) {
				json_object *json_nxt = NULL;
				const char *print_store;


				if (CHECK_FLAG(p->cap, PEER_CAP_ENHE_ADV) &&
				    CHECK_FLAG(p->cap, PEER_CAP_ENHE_RCV))
					json_object_string_add(
						json_cap, "extendedNexthop",
						"advertisedAndReceived");
				else if (CHECK_FLAG(p->cap, PEER_CAP_ENHE_ADV))
					json_object_string_add(
						json_cap, "extendedNexthop",
						"advertised");
				else if (CHECK_FLAG(p->cap, PEER_CAP_ENHE_RCV))
					json_object_string_add(
						json_cap, "extendedNexthop",
						"received");

				if (CHECK_FLAG(p->cap, PEER_CAP_ENHE_RCV)) {
					json_nxt = json_object_new_object();

					for (safi = SAFI_UNICAST;
					     safi < SAFI_MAX; safi++) {
						if (CHECK_FLAG(
							    p->af_cap[AFI_IP]
								     [safi],
							    PEER_CAP_ENHE_AF_RCV)) {
							print_store =
								get_afi_safi_str(
									AFI_IP,
									safi,
									true);
							json_object_string_add(
								json_nxt,
								print_store,
								"recieved"); /* misspelled for compatibility */
						}
					}
					json_object_object_add(
						json_cap,
						"extendedNexthopFamililesByPeer",
						json_nxt);
				}
			}

			/* Long-lived Graceful Restart */
			if (CHECK_FLAG(p->cap, PEER_CAP_LLGR_RCV) ||
			    CHECK_FLAG(p->cap, PEER_CAP_LLGR_ADV)) {
				json_object *json_llgr = NULL;
				const char *afi_safi_str;

				if (CHECK_FLAG(p->cap, PEER_CAP_LLGR_ADV) &&
				    CHECK_FLAG(p->cap, PEER_CAP_LLGR_RCV))
					json_object_string_add(
						json_cap,
						"longLivedGracefulRestart",
						"advertisedAndReceived");
				else if (CHECK_FLAG(p->cap, PEER_CAP_LLGR_ADV))
					json_object_string_add(
						json_cap,
						"longLivedGracefulRestart",
						"advertised");
				else if (CHECK_FLAG(p->cap, PEER_CAP_LLGR_RCV))
					json_object_string_add(
						json_cap,
						"longLivedGracefulRestart",
						"received");

				if (CHECK_FLAG(p->cap, PEER_CAP_LLGR_RCV)) {
					json_llgr = json_object_new_object();

					FOREACH_AFI_SAFI (afi, safi) {
						if (CHECK_FLAG(
							    p->af_cap[afi]
								     [safi],
							    PEER_CAP_ENHE_AF_RCV)) {
							afi_safi_str =
								get_afi_safi_str(
									afi,
									safi,
									true);
							json_object_string_add(
								json_llgr,
								afi_safi_str,
								"received");
						}
					}
					json_object_object_add(
						json_cap,
						"longLivedGracefulRestartByPeer",
						json_llgr);
				}
			}

			/* Route Refresh */
			if (CHECK_FLAG(p->cap, PEER_CAP_REFRESH_ADV) ||
			    CHECK_FLAG(p->cap, PEER_CAP_REFRESH_RCV)) {
				if (CHECK_FLAG(p->cap, PEER_CAP_REFRESH_ADV) &&
				    CHECK_FLAG(p->cap, PEER_CAP_REFRESH_RCV))
					json_object_string_add(json_cap,
							       "routeRefresh",
							       "advertisedAndReceived");
				else if (CHECK_FLAG(p->cap,
						    PEER_CAP_REFRESH_ADV))
					json_object_string_add(json_cap,
							       "routeRefresh",
							       "advertised");
				else if (CHECK_FLAG(p->cap,
						    PEER_CAP_REFRESH_RCV))
					json_object_string_add(json_cap,
							       "routeRefresh",
							       "received");
			}

			/* Enhanced Route Refresh */
			if (CHECK_FLAG(p->cap, PEER_CAP_ENHANCED_RR_ADV) ||
			    CHECK_FLAG(p->cap, PEER_CAP_ENHANCED_RR_RCV)) {
				if (CHECK_FLAG(p->cap,
					       PEER_CAP_ENHANCED_RR_ADV) &&
				    CHECK_FLAG(p->cap,
					       PEER_CAP_ENHANCED_RR_RCV))
					json_object_string_add(
						json_cap,
						"enhancedRouteRefresh",
						"advertisedAndReceived");
				else if (CHECK_FLAG(p->cap,
						    PEER_CAP_ENHANCED_RR_ADV))
					json_object_string_add(
						json_cap,
						"enhancedRouteRefresh",
						"advertised");
				else if (CHECK_FLAG(p->cap,
						    PEER_CAP_ENHANCED_RR_RCV))
					json_object_string_add(
						json_cap,
						"enhancedRouteRefresh",
						"received");
			}

			/* Multiprotocol Extensions */
			json_object *json_multi = NULL;

			json_multi = json_object_new_object();

			FOREACH_AFI_SAFI (afi, safi) {
				if (p->afc_adv[afi][safi] ||
				    p->afc_recv[afi][safi]) {
					json_object *json_exten = NULL;
					json_exten = json_object_new_object();

					if (p->afc_adv[afi][safi] &&
					    p->afc_recv[afi][safi])
						json_object_boolean_true_add(
							json_exten,
							"advertisedAndReceived");
					else if (p->afc_adv[afi][safi])
						json_object_boolean_true_add(
							json_exten,
							"advertised");
					else if (p->afc_recv[afi][safi])
						json_object_boolean_true_add(
							json_exten, "received");

					json_object_object_add(
						json_multi,
						get_afi_safi_str(afi, safi,
								 true),
						json_exten);
				}
			}
			json_object_object_add(json_cap,
					       "multiprotocolExtensions",
					       json_multi);

			/* Hostname capabilities */
			json_object *json_hname = NULL;

			json_hname = json_object_new_object();

			if (CHECK_FLAG(p->cap, PEER_CAP_HOSTNAME_ADV)) {
				json_object_string_add(
					json_hname, "advHostName",
					bgp->peer_self->hostname
						? bgp->peer_self->hostname
						: "n/a");
				json_object_string_add(
					json_hname, "advDomainName",
					bgp->peer_self->domainname
						? bgp->peer_self->domainname
						: "n/a");
			}


			if (CHECK_FLAG(p->cap, PEER_CAP_HOSTNAME_RCV)) {
				json_object_string_add(
					json_hname, "rcvHostName",
					p->hostname ? p->hostname : "n/a");
				json_object_string_add(
					json_hname, "rcvDomainName",
					p->domainname ? p->domainname : "n/a");
			}

			json_object_object_add(json_cap, "hostName",
					       json_hname);

			/* Software Version capability */
			json_object *json_soft_version = NULL;

			json_soft_version = json_object_new_object();

			if (CHECK_FLAG(p->cap, PEER_CAP_SOFT_VERSION_ADV))
				json_object_string_add(
					json_soft_version,
					"advertisedSoftwareVersion",
					cmd_software_version_get());

			if (CHECK_FLAG(p->cap, PEER_CAP_SOFT_VERSION_RCV))
				json_object_string_add(
					json_soft_version,
					"receivedSoftwareVersion",
					p->soft_version ? p->soft_version
							: "n/a");

			json_object_object_add(json_cap, "softwareVersion",
					       json_soft_version);

			/* Link-Local Next Hop capability */
			json_object *json_link_local = NULL;

			json_link_local = json_object_new_object();
			json_object_boolean_add(json_link_local, "advertised",
						!!CHECK_FLAG(p->cap, PEER_CAP_LINK_LOCAL_ADV));
			json_object_boolean_add(json_link_local, "received",
						!!CHECK_FLAG(p->cap, PEER_CAP_LINK_LOCAL_RCV));
			json_object_object_add(json_cap, "linkLocalNextHop", json_link_local);

			/* Graceful Restart */
			bgp_show_peer_gr_capability(vty, p, use_json, json_cap);
			json_object_object_add(
				json_neigh, "neighborCapabilities", json_cap);
		} else {
			vty_out(vty, "  Neighbor capabilities:\n");

			/* AS4 */
			if (CHECK_FLAG(p->cap, PEER_CAP_AS4_RCV) ||
			    CHECK_FLAG(p->cap, PEER_CAP_AS4_ADV)) {
				vty_out(vty, "    4 Byte AS:");
				if (CHECK_FLAG(p->cap, PEER_CAP_AS4_ADV))
					vty_out(vty, " advertised");
				if (CHECK_FLAG(p->cap, PEER_CAP_AS4_RCV))
					vty_out(vty, " %sreceived",
						CHECK_FLAG(p->cap,
							   PEER_CAP_AS4_ADV)
							? "and "
							: "");
				vty_out(vty, "\n");
			}

			/* Extended Message Support */
			if (CHECK_FLAG(p->cap, PEER_CAP_EXTENDED_MESSAGE_RCV) ||
			    CHECK_FLAG(p->cap, PEER_CAP_EXTENDED_MESSAGE_ADV)) {
				vty_out(vty, "    Extended Message:");
				if (CHECK_FLAG(p->cap,
					       PEER_CAP_EXTENDED_MESSAGE_ADV))
					vty_out(vty, " advertised");
				if (CHECK_FLAG(p->cap,
					       PEER_CAP_EXTENDED_MESSAGE_RCV))
					vty_out(vty, " %sreceived",
						CHECK_FLAG(
							p->cap,
							PEER_CAP_EXTENDED_MESSAGE_ADV)
							? "and "
							: "");
				vty_out(vty, "\n");
			}

			/* AddPath */
			if (CHECK_FLAG(p->cap, PEER_CAP_ADDPATH_RCV) ||
			    CHECK_FLAG(p->cap, PEER_CAP_ADDPATH_ADV)) {
				vty_out(vty, "    AddPath:\n");

				FOREACH_AFI_SAFI (afi, safi) {
					if (CHECK_FLAG(
						    p->af_cap[afi][safi],
						    PEER_CAP_ADDPATH_AF_TX_ADV) ||
					    CHECK_FLAG(
						    p->af_cap[afi][safi],
						    PEER_CAP_ADDPATH_AF_TX_RCV)) {
						vty_out(vty, "      %s: TX ",
							get_afi_safi_str(
								afi, safi,
								false));

						if (CHECK_FLAG(
							    p->af_cap[afi]
								     [safi],
							    PEER_CAP_ADDPATH_AF_TX_ADV))
							vty_out(vty,
								"advertised");

						if (CHECK_FLAG(
							    p->af_cap[afi]
								     [safi],
							    PEER_CAP_ADDPATH_AF_TX_RCV))
							vty_out(vty,
								"%sreceived",
								CHECK_FLAG(
									p->af_cap
										[afi]
										[safi],
									PEER_CAP_ADDPATH_AF_TX_ADV)
									? " and "
									: "");

						vty_out(vty, "\n");
					}

					if (CHECK_FLAG(
						    p->af_cap[afi][safi],
						    PEER_CAP_ADDPATH_AF_RX_ADV) ||
					    CHECK_FLAG(
						    p->af_cap[afi][safi],
						    PEER_CAP_ADDPATH_AF_RX_RCV)) {
						vty_out(vty, "      %s: RX ",
							get_afi_safi_str(
								afi, safi,
								false));

						if (CHECK_FLAG(
							    p->af_cap[afi]
								     [safi],
							    PEER_CAP_ADDPATH_AF_RX_ADV))
							vty_out(vty,
								"advertised");

						if (CHECK_FLAG(
							    p->af_cap[afi]
								     [safi],
							    PEER_CAP_ADDPATH_AF_RX_RCV))
							vty_out(vty,
								"%sreceived",
								CHECK_FLAG(
									p->af_cap
										[afi]
										[safi],
									PEER_CAP_ADDPATH_AF_RX_ADV)
									? " and "
									: "");

						vty_out(vty, "\n");
					}
				}
			}

			/* Paths-Limit */
			if (CHECK_FLAG(p->cap, PEER_CAP_PATHS_LIMIT_RCV) ||
			    CHECK_FLAG(p->cap, PEER_CAP_PATHS_LIMIT_ADV)) {
				vty_out(vty, "    Paths-Limit:\n");

				FOREACH_AFI_SAFI (afi, safi) {
					if (CHECK_FLAG(p->af_cap[afi][safi],
						       PEER_CAP_PATHS_LIMIT_AF_ADV) ||
					    CHECK_FLAG(p->af_cap[afi][safi],
						       PEER_CAP_PATHS_LIMIT_AF_RCV)) {
						vty_out(vty, "      %s: ",
							get_afi_safi_str(afi,
									 safi,
									 false));

						if (CHECK_FLAG(p->af_cap[afi][safi],
							       PEER_CAP_PATHS_LIMIT_AF_ADV))
							vty_out(vty,
								"advertised (%u)",
								p->addpath_paths_limit
									[afi][safi]
										.send);

						if (CHECK_FLAG(p->af_cap[afi][safi],
							       PEER_CAP_PATHS_LIMIT_AF_RCV))
							vty_out(vty,
								"%sreceived (%u)",
								CHECK_FLAG(p->af_cap[afi]
										    [safi],
									   PEER_CAP_PATHS_LIMIT_AF_ADV)
									? " and "
									: "",
								p->addpath_paths_limit
									[afi][safi]
										.receive);

						vty_out(vty, "\n");
					}
				}
			}

			/* Dynamic */
			if (CHECK_FLAG(p->cap, PEER_CAP_DYNAMIC_RCV) ||
			    CHECK_FLAG(p->cap, PEER_CAP_DYNAMIC_ADV)) {
				vty_out(vty, "    Dynamic:");
				if (CHECK_FLAG(p->cap, PEER_CAP_DYNAMIC_ADV))
					vty_out(vty, " advertised");
				if (CHECK_FLAG(p->cap, PEER_CAP_DYNAMIC_RCV))
					vty_out(vty, " %sreceived",
						CHECK_FLAG(p->cap,
							   PEER_CAP_DYNAMIC_ADV)
							? "and "
							: "");
				vty_out(vty, "\n");
			}

			/* Role */
			if (CHECK_FLAG(p->cap, PEER_CAP_ROLE_RCV) ||
			    CHECK_FLAG(p->cap, PEER_CAP_ROLE_ADV)) {
				vty_out(vty, "    Role:");
				if (CHECK_FLAG(p->cap, PEER_CAP_ROLE_ADV))
					vty_out(vty, " advertised");
				if (CHECK_FLAG(p->cap, PEER_CAP_ROLE_RCV))
					vty_out(vty, " %sreceived",
						CHECK_FLAG(p->cap,
							   PEER_CAP_ROLE_ADV)
							? "and "
							: "");
				vty_out(vty, "\n");
			}

			/* Extended nexthop */
			if (CHECK_FLAG(p->cap, PEER_CAP_ENHE_RCV) ||
			    CHECK_FLAG(p->cap, PEER_CAP_ENHE_ADV)) {
				vty_out(vty, "    Extended nexthop:");
				if (CHECK_FLAG(p->cap, PEER_CAP_ENHE_ADV))
					vty_out(vty, " advertised");
				if (CHECK_FLAG(p->cap, PEER_CAP_ENHE_RCV))
					vty_out(vty, " %sreceived",
						CHECK_FLAG(p->cap,
							   PEER_CAP_ENHE_ADV)
							? "and "
							: "");
				vty_out(vty, "\n");

				if (CHECK_FLAG(p->cap, PEER_CAP_ENHE_RCV)) {
					vty_out(vty,
						"      Address families by peer:\n        ");
					for (safi = SAFI_UNICAST;
					     safi < SAFI_MAX; safi++)
						if (CHECK_FLAG(
							    p->af_cap[AFI_IP]
								     [safi],
							    PEER_CAP_ENHE_AF_RCV))
							vty_out(vty,
								"           %s\n",
								get_afi_safi_str(
									AFI_IP,
									safi,
									false));
				}
			}

			/* Long-lived Graceful Restart */
			if (CHECK_FLAG(p->cap, PEER_CAP_LLGR_RCV) ||
			    CHECK_FLAG(p->cap, PEER_CAP_LLGR_ADV)) {
				vty_out(vty,
					"    Long-lived Graceful Restart:");
				if (CHECK_FLAG(p->cap, PEER_CAP_LLGR_ADV))
					vty_out(vty, " advertised");
				if (CHECK_FLAG(p->cap, PEER_CAP_LLGR_RCV))
					vty_out(vty, " %sreceived",
						CHECK_FLAG(p->cap,
							   PEER_CAP_LLGR_ADV)
							? "and "
							: "");
				vty_out(vty, "\n");

				if (CHECK_FLAG(p->cap, PEER_CAP_LLGR_RCV)) {
					vty_out(vty,
						"      Address families by peer:\n");
					FOREACH_AFI_SAFI (afi, safi)
						if (CHECK_FLAG(
							    p->af_cap[afi]
								     [safi],
							    PEER_CAP_LLGR_AF_RCV))
							vty_out(vty,
								"           %s\n",
								get_afi_safi_str(
									afi,
									safi,
									false));
				}
			}

			/* Route Refresh */
			if (CHECK_FLAG(p->cap, PEER_CAP_REFRESH_ADV) ||
			    CHECK_FLAG(p->cap, PEER_CAP_REFRESH_RCV)) {
				vty_out(vty, "    Route refresh:");
				if (CHECK_FLAG(p->cap, PEER_CAP_REFRESH_ADV))
					vty_out(vty, " advertised");
				if (CHECK_FLAG(p->cap, PEER_CAP_REFRESH_RCV))
					vty_out(vty, " %sreceived",
						CHECK_FLAG(p->cap,
							   PEER_CAP_REFRESH_ADV)
							? "and "
							: "");
				vty_out(vty, "\n");
			}

			/* Enhanced Route Refresh */
			if (CHECK_FLAG(p->cap, PEER_CAP_ENHANCED_RR_ADV) ||
			    CHECK_FLAG(p->cap, PEER_CAP_ENHANCED_RR_RCV)) {
				vty_out(vty, "    Enhanced Route Refresh:");
				if (CHECK_FLAG(p->cap,
					       PEER_CAP_ENHANCED_RR_ADV))
					vty_out(vty, " advertised");
				if (CHECK_FLAG(p->cap,
					       PEER_CAP_ENHANCED_RR_RCV))
					vty_out(vty, " %sreceived",
						CHECK_FLAG(p->cap,
							   PEER_CAP_REFRESH_ADV)
							? "and "
							: "");
				vty_out(vty, "\n");
			}

			/* Multiprotocol Extensions */
			FOREACH_AFI_SAFI (afi, safi)
				if (p->afc_adv[afi][safi] ||
				    p->afc_recv[afi][safi]) {
					vty_out(vty, "    Address Family %s:",
						get_afi_safi_str(afi, safi,
								 false));
					if (p->afc_adv[afi][safi])
						vty_out(vty, " advertised");
					if (p->afc_recv[afi][safi])
						vty_out(vty, " %sreceived",
							p->afc_adv[afi][safi]
								? "and "
								: "");
					vty_out(vty, "\n");
				}

			/* Hostname capability */
			vty_out(vty, "    Hostname Capability:");

			if (CHECK_FLAG(p->cap, PEER_CAP_HOSTNAME_ADV)) {
				vty_out(vty,
					" advertised (name: %s,domain name: %s)",
					bgp->peer_self->hostname
						? bgp->peer_self->hostname
						: "n/a",
					bgp->peer_self->domainname
						? bgp->peer_self->domainname
						: "n/a");
			} else {
				vty_out(vty, " not advertised");
			}

			if (CHECK_FLAG(p->cap, PEER_CAP_HOSTNAME_RCV)) {
				vty_out(vty,
					" received (name: %s,domain name: %s)",
					p->hostname ? p->hostname : "n/a",
					p->domainname ? p->domainname : "n/a");
			} else {
				vty_out(vty, " not received");
			}

			vty_out(vty, "\n");

			/* Software Version capability */
			vty_out(vty, "    Version Capability:");

			if (CHECK_FLAG(p->cap, PEER_CAP_SOFT_VERSION_ADV)) {
				vty_out(vty,
					" advertised software version (%s)",
					cmd_software_version_get());
			} else
				vty_out(vty, " not advertised");

			if (CHECK_FLAG(p->cap, PEER_CAP_SOFT_VERSION_RCV)) {
				vty_out(vty, " received software version (%s)",
					p->soft_version ? p->soft_version
							: "n/a");
			} else
				vty_out(vty, " not received");

			vty_out(vty, "\n");

			/* Link-Local Next Hop capability */
			vty_out(vty, "    Link-Local Next Hop Capability:");

			if (CHECK_FLAG(p->cap, PEER_CAP_LINK_LOCAL_ADV))
				vty_out(vty, " advertised link-local");
			else
				vty_out(vty, " not advertised");

			if (CHECK_FLAG(p->cap, PEER_CAP_LINK_LOCAL_RCV))
				vty_out(vty, " received link-local");
			else
				vty_out(vty, " not received");

			vty_out(vty, "\n");

			/* Graceful Restart */
			if (CHECK_FLAG(p->cap, PEER_CAP_RESTART_RCV) ||
			    CHECK_FLAG(p->cap, PEER_CAP_RESTART_ADV)) {
				vty_out(vty,
					"    Graceful Restart Capability:");
				if (CHECK_FLAG(p->cap, PEER_CAP_RESTART_ADV))
					vty_out(vty, " advertised");
				if (CHECK_FLAG(p->cap, PEER_CAP_RESTART_RCV))
					vty_out(vty, " %sreceived",
						CHECK_FLAG(p->cap,
							   PEER_CAP_RESTART_ADV)
							? "and "
							: "");
				vty_out(vty, "\n");

				if (CHECK_FLAG(p->cap, PEER_CAP_RESTART_RCV)) {
					vty_out(vty,
						"      Remote Restart timer is %d seconds\n",
						p->v_gr_restart);
					vty_out(vty,
						"      Address families by peer:\n        ");

					/* Graceful Restart */
					bgp_show_peer_gr_capability(vty, p, use_json, NULL);
				}
			}
		}
	}

	/* graceful restart information */
	bgp_show_peer_gr_extra_info(vty, p, use_json, json_neigh);

	if (use_json) {
		json_object *json_pfx_stat = NULL;

		json_stat = json_object_new_object();
		json_pfx_stat = json_object_new_object();

		/* Packet counts. */
		atomic_size_t outq_count, inq_count;
		outq_count = atomic_load_explicit(&p->connection->obuf->count,
						  memory_order_relaxed);
		inq_count = atomic_load_explicit(&p->connection->ibuf->count,
						 memory_order_relaxed);

		json_object_int_add(json_stat, "depthInq",
				    (unsigned long)inq_count);
		json_object_int_add(json_stat, "depthOutq",
				    (unsigned long)outq_count);
		json_object_int_add(json_stat, "opensSent",
				    atomic_load_explicit(&p->open_out,
							 memory_order_relaxed));
		json_object_int_add(json_stat, "opensRecv",
				    atomic_load_explicit(&p->open_in,
							 memory_order_relaxed));
		json_object_int_add(json_stat, "notificationsSent",
				    atomic_load_explicit(&p->notify_out,
							 memory_order_relaxed));
		json_object_int_add(json_stat, "notificationsRecv",
				    atomic_load_explicit(&p->notify_in,
							 memory_order_relaxed));
		json_object_int_add(json_stat, "updatesSent",
				    atomic_load_explicit(&p->update_out,
							 memory_order_relaxed));
		json_object_int_add(json_stat, "updatesRecv",
				    atomic_load_explicit(&p->update_in,
							 memory_order_relaxed));
		json_object_int_add(json_stat, "keepalivesSent",
				    atomic_load_explicit(&p->keepalive_out,
							 memory_order_relaxed));
		json_object_int_add(json_stat, "keepalivesRecv",
				    atomic_load_explicit(&p->keepalive_in,
							 memory_order_relaxed));
		json_object_int_add(json_stat, "routeRefreshSent",
				    atomic_load_explicit(&p->refresh_out,
							 memory_order_relaxed));
		json_object_int_add(json_stat, "routeRefreshRecv",
				    atomic_load_explicit(&p->refresh_in,
							 memory_order_relaxed));
		json_object_int_add(json_stat, "capabilitySent",
				    atomic_load_explicit(&p->dynamic_cap_out,
							 memory_order_relaxed));
		json_object_int_add(json_stat, "capabilityRecv",
				    atomic_load_explicit(&p->dynamic_cap_in,
							 memory_order_relaxed));
		json_object_int_add(json_stat, "totalSent", PEER_TOTAL_TX(p));
		json_object_int_add(json_stat, "totalRecv", PEER_TOTAL_RX(p));
		json_object_object_add(json_neigh, "messageStats", json_stat);

		/* Prefix statistics */
		json_object_int_add(json_pfx_stat, "inboundFiltered", p->stat_pfx_filter);
		json_object_int_add(json_pfx_stat, "aspathLoop", p->stat_pfx_aspath_loop);
		json_object_int_add(json_pfx_stat, "originatorLoop", p->stat_pfx_originator_loop);
		json_object_int_add(json_pfx_stat, "clusterLoop", p->stat_pfx_cluster_loop);
		json_object_int_add(json_pfx_stat, "invalidNextHop", p->stat_pfx_nh_invalid);
		json_object_int_add(json_pfx_stat, "withdrawn", p->stat_pfx_withdraw);
		json_object_int_add(json_pfx_stat, "attributesDiscarded", p->stat_pfx_discard);
		json_object_object_add(json_neigh, "prefixStats", json_pfx_stat);
	} else {
		atomic_size_t outq_count, inq_count, open_out, open_in,
			notify_out, notify_in, update_out, update_in,
			keepalive_out, keepalive_in, refresh_out, refresh_in,
			dynamic_cap_out, dynamic_cap_in;
		outq_count = atomic_load_explicit(&p->connection->obuf->count,
						  memory_order_relaxed);
		inq_count = atomic_load_explicit(&p->connection->ibuf->count,
						 memory_order_relaxed);
		open_out = atomic_load_explicit(&p->open_out,
						memory_order_relaxed);
		open_in =
			atomic_load_explicit(&p->open_in, memory_order_relaxed);
		notify_out = atomic_load_explicit(&p->notify_out,
						  memory_order_relaxed);
		notify_in = atomic_load_explicit(&p->notify_in,
						 memory_order_relaxed);
		update_out = atomic_load_explicit(&p->update_out,
						  memory_order_relaxed);
		update_in = atomic_load_explicit(&p->update_in,
						 memory_order_relaxed);
		keepalive_out = atomic_load_explicit(&p->keepalive_out,
						     memory_order_relaxed);
		keepalive_in = atomic_load_explicit(&p->keepalive_in,
						    memory_order_relaxed);
		refresh_out = atomic_load_explicit(&p->refresh_out,
						   memory_order_relaxed);
		refresh_in = atomic_load_explicit(&p->refresh_in,
						  memory_order_relaxed);
		dynamic_cap_out = atomic_load_explicit(&p->dynamic_cap_out,
						       memory_order_relaxed);
		dynamic_cap_in = atomic_load_explicit(&p->dynamic_cap_in,
						      memory_order_relaxed);

		/* Packet counts. */
		vty_out(vty, "  Message statistics:\n");
		vty_out(vty, "    Inq depth is %zu\n", inq_count);
		vty_out(vty, "    Outq depth is %zu\n", outq_count);
		vty_out(vty, "                         Sent       Rcvd\n");
		vty_out(vty, "    Opens:         %10zu %10zu\n", open_out,
			open_in);
		vty_out(vty, "    Notifications: %10zu %10zu\n", notify_out,
			notify_in);
		vty_out(vty, "    Updates:       %10zu %10zu\n", update_out,
			update_in);
		vty_out(vty, "    Keepalives:    %10zu %10zu\n", keepalive_out,
			keepalive_in);
		vty_out(vty, "    Route Refresh: %10zu %10zu\n", refresh_out,
			refresh_in);
		vty_out(vty, "    Capability:    %10zu %10zu\n",
			dynamic_cap_out, dynamic_cap_in);
		vty_out(vty, "    Total:         %10u %10u\n\n", (uint32_t)PEER_TOTAL_TX(p),
			(uint32_t)PEER_TOTAL_RX(p));

		/* Prefix statistics */
		vty_out(vty, "  Prefix statistics:\n");
		vty_out(vty, "    Inbound filtered: %u\n", p->stat_pfx_filter);
		vty_out(vty, "    AS-PATH loop: %u\n", p->stat_pfx_aspath_loop);
		vty_out(vty, "    Originator loop: %u\n", p->stat_pfx_originator_loop);
		vty_out(vty, "    Cluster loop: %u\n", p->stat_pfx_cluster_loop);
		vty_out(vty, "    Invalid next-hop: %u\n", p->stat_pfx_nh_invalid);
		vty_out(vty, "    Withdrawn: %u\n", p->stat_pfx_withdraw);
		vty_out(vty, "    Attributes discarded: %u\n\n", p->stat_pfx_discard);
	}

	if (use_json) {
		/* advertisement-interval */
		json_object_int_add(json_neigh,
				    "minBtwnAdvertisementRunsTimerMsecs",
				    p->v_routeadv * 1000);

		/* Update-source. */
		if (p->update_if || p->update_source) {
			if (p->update_if)
				json_object_string_add(json_neigh,
						       "updateSource",
						       p->update_if);
			else if (p->update_source)
				json_object_string_addf(json_neigh,
							"updateSource", "%pSU",
							p->update_source);
		}

		/* update-delay timer */
		json_object_int_add(json_neigh, "bgpUpdateDelayTimerMsecs",
				    bgp->v_update_delay * 1000);
		json_object_int_add(json_neigh, "bgpUpdateDelayTimerMsecsRemaining",
				    event_timer_remain_second(bgp->t_update_delay) * 1000);
	} else {
		/* advertisement-interval */
		vty_out(vty,
			"  Minimum time between advertisement runs is %d seconds\n",
			p->v_routeadv);

		/* update delay timer */
		vty_out(vty, "  Update delay timer is %u seconds (remaining: %lu)\n",
			bgp->v_update_delay, event_timer_remain_second(bgp->t_update_delay));

		/* Update-source. */
		if (p->update_if || p->update_source) {
			vty_out(vty, "  Update source is ");
			if (p->update_if)
				vty_out(vty, "%s", p->update_if);
			else if (p->update_source)
				vty_out(vty, "%pSU", p->update_source);
			vty_out(vty, "\n");
		}

		vty_out(vty, "\n");
	}

	/* Address Family Information */
	json_object *json_hold = NULL;

	if (use_json)
		json_hold = json_object_new_object();

	FOREACH_AFI_SAFI (afi, safi)
		if (p->afc[afi][safi])
			bgp_show_peer_afi(vty, p, afi, safi, use_json,
					  json_hold);

	if (use_json) {
		json_object_object_add(json_neigh, "addressFamilyInfo",
				       json_hold);
		json_object_int_add(json_neigh, "connectionsEstablished",
				    p->established);
		json_object_int_add(json_neigh, "connectionsDropped",
				    p->dropped);
	} else
		vty_out(vty, "  Connections established %d; dropped %d\n",
			p->established, p->dropped);

	if (p->last_reset == PEER_DOWN_NONE) {
		if (use_json)
			json_object_string_add(json_neigh, "lastReset",
					       peer_down_str[PEER_DOWN_NONE]);
		else
			vty_out(vty, "  Last reset %s\n", peer_down_str[PEER_DOWN_NONE]);
	} else {
		if (use_json) {
			time_t uptime;

			uptime = monotime(NULL);
			uptime -= p->resettime;

			json_object_int_add(json_neigh, "lastResetTimerMsecs",
					    (int64_t)uptime * 1000);
			bgp_show_peer_reset(NULL, p, json_neigh, true);
		} else {
			vty_out(vty, "  Last reset %s, ",
				peer_uptime(p->resettime, timebuf,
					    BGP_UPTIME_LEN, 0, NULL));

			bgp_show_peer_reset(vty, p, NULL, false);
			if (p->last_reset_cause) {
				msg = p->last_reset_cause->data;
				vty_out(vty,
					"  Message received that caused BGP to send a NOTIFICATION:\n    ");
				for (i = 1; i <= p->last_reset_cause->size;
				     i++) {
					vty_out(vty, "%02X", *msg++);

					if (i != p->last_reset_cause->size) {
						if (i % 16 == 0) {
							vty_out(vty, "\n    ");
						} else if (i % 4 == 0) {
							vty_out(vty, " ");
						}
					}
				}
				vty_out(vty, "\n");
			}
		}
	}

	if (CHECK_FLAG(p->sflags, PEER_STATUS_PREFIX_OVERFLOW)) {
		if (use_json)
			json_object_boolean_true_add(json_neigh,
						     "prefixesConfigExceedMax");
		else
			vty_out(vty,
				"  Peer had exceeded the max. no. of prefixes configured.\n");

		if (event_is_scheduled(p->connection->t_pmax_restart)) {
			if (use_json) {
				json_object_boolean_true_add(
					json_neigh, "reducePrefixNumFrom");
				json_object_int_add(json_neigh,
						    "restartInTimerMsec",
						    event_timer_remain_second(
							    p->connection
								    ->t_pmax_restart) *
							    1000);
			} else
				vty_out(vty,
					"  Reduce the no. of prefix from %s, will restart in %ld seconds\n",
					p->host,
					event_timer_remain_second(
						p->connection->t_pmax_restart));
		} else {
			if (use_json)
				json_object_boolean_true_add(
					json_neigh,
					"reducePrefixNumAndClearIpBgp");
			else
				vty_out(vty,
					"  Reduce the no. of prefix and clear ip bgp %s to restore peering\n",
					p->host);
		}
	}

	/* EBGP Multihop and GTSM */
	if (p->sort != BGP_PEER_IBGP) {
		if (use_json) {
			if (p->gtsm_hops > BGP_GTSM_HOPS_DISABLED)
				json_object_int_add(json_neigh,
						    "externalBgpNbrMaxHopsAway",
						    p->gtsm_hops);
			else
				json_object_int_add(json_neigh,
						    "externalBgpNbrMaxHopsAway",
						    p->ttl);
		} else {
			if (p->gtsm_hops > BGP_GTSM_HOPS_DISABLED)
				vty_out(vty,
					"  External BGP neighbor may be up to %d hops away.\n",
					p->gtsm_hops);
			else
				vty_out(vty,
					"  External BGP neighbor may be up to %d hops away.\n",
					p->ttl);
		}
	} else {
		if (use_json) {
			if (p->gtsm_hops > BGP_GTSM_HOPS_DISABLED)
				json_object_int_add(json_neigh,
						    "internalBgpNbrMaxHopsAway",
						    p->gtsm_hops);
			else
				json_object_int_add(json_neigh,
						    "internalBgpNbrMaxHopsAway",
						    p->ttl);
		} else {
			if (p->gtsm_hops > BGP_GTSM_HOPS_DISABLED)
				vty_out(vty,
					"  Internal BGP neighbor may be up to %d hops away.\n",
					p->gtsm_hops);
			else
				vty_out(vty,
					"  Internal BGP neighbor may be up to %d hops away.\n",
					p->ttl);
		}
	}

	/* Local address. */
	if (p->connection->su_local) {
		if (use_json) {
			json_object_string_addf(json_neigh, "hostLocal", "%pSU",
						p->connection->su_local);
			json_object_int_add(json_neigh, "portLocal",
					    ntohs(p->connection->su_local->sin.sin_port));
		} else
			vty_out(vty, "Local host: %pSU, Local port: %d\n", p->connection->su_local,
				ntohs(p->connection->su_local->sin.sin_port));
	} else {
		if (use_json) {
			json_object_string_add(json_neigh, "hostLocal",
					       "Unknown");
			json_object_int_add(json_neigh, "portLocal", -1);
		}
	}

	/* Remote address. */
	if (p->connection->su_remote) {
		if (use_json) {
			json_object_string_addf(json_neigh, "hostForeign", "%pSU",
						p->connection->su_remote);
			json_object_int_add(json_neigh, "portForeign",
					    ntohs(p->connection->su_remote->sin.sin_port));
		} else
			vty_out(vty, "Foreign host: %pSU, Foreign port: %d\n",
				p->connection->su_remote,
				ntohs(p->connection->su_remote->sin.sin_port));
	} else {
		if (use_json) {
			json_object_string_add(json_neigh, "hostForeign",
					       "Unknown");
			json_object_int_add(json_neigh, "portForeign", -1);
		}
	}

	/* Nexthop display. */
	if (p->connection->su_local) {
		if (use_json) {
			json_object_string_addf(json_neigh, "nexthop", "%pI4",
						&p->nexthop.v4);
			json_object_string_addf(json_neigh, "nexthopGlobal",
						"%pI6", &p->nexthop.v6_global);
			json_object_string_addf(json_neigh, "nexthopLocal",
						"%pI6", &p->nexthop.v6_local);
			if (p->shared_network)
				json_object_string_add(json_neigh,
						       "bgpConnection",
						       "sharedNetwork");
			else
				json_object_string_add(json_neigh,
						       "bgpConnection",
						       "nonSharedNetwork");
		} else {
			vty_out(vty, "Nexthop: %pI4\n", &p->nexthop.v4);
			vty_out(vty, "Nexthop global: %pI6\n",
				&p->nexthop.v6_global);
			vty_out(vty, "Nexthop local: %pI6\n",
				&p->nexthop.v6_local);
			vty_out(vty, "BGP connection: %s\n",
				p->shared_network ? "shared network"
						  : "non shared network");
		}
	} else {
		if (use_json) {
			json_object_string_add(json_neigh, "nexthop",
					       "Unknown");
			json_object_string_add(json_neigh, "nexthopGlobal",
					       "Unknown");
			json_object_string_add(json_neigh, "nexthopLocal",
					       "Unknown");
			json_object_string_add(json_neigh, "bgpConnection",
					       "Unknown");
		}
	}

	/* Timer information. */
	if (use_json) {
		json_object_int_add(json_neigh, "connectRetryTimer",
				    p->v_connect);
		if (peer_established(p->connection)) {
			json_object_int_add(json_neigh, "estimatedRttInMsecs",
					    p->rtt);
			if (CHECK_FLAG(p->flags, PEER_FLAG_RTT_SHUTDOWN)) {
				json_object_int_add(json_neigh,
						    "shutdownRttInMsecs",
						    p->rtt_expected);
				json_object_int_add(json_neigh,
						    "shutdownRttAfterCount",
						    p->rtt_keepalive_rcv);
			}
		}
		if (p->bfd_config) {
			json_object_int_add(json_neigh, "bfdHoldTimerExpireInMsecs",
					    event_timer_remain_second(p->bfd_config->t_hold_timer) *
						    1000);
			json_object_boolean_add(json_neigh, "bfdHoldTimerExpired",
						!!CHECK_FLAG(p->sflags,
							     PEER_STATUS_BFD_STRICT_HOLD_TIME_EXPIRED));
			json_object_boolean_add(json_neigh, "bfdStrictHold",
						!!CHECK_FLAG(p->sflags,
							     PEER_STATUS_BFD_STRICT_HOLD));
		}
		if (event_is_scheduled(p->connection->t_start))
			json_object_int_add(json_neigh,
					    "nextStartTimerDueInMsecs",
					    event_timer_remain_second(
						    p->connection->t_start) *
						    1000);
		if (event_is_scheduled(p->connection->t_connect))
			json_object_int_add(json_neigh,
					    "nextConnectTimerDueInMsecs",
					    event_timer_remain_second(
						    p->connection->t_connect) *
						    1000);
		if (event_is_scheduled(p->connection->t_routeadv)) {
			json_object_int_add(json_neigh, "mraiInterval",
					    p->v_routeadv);
			json_object_int_add(json_neigh, "mraiTimerExpireInMsecs",
					    event_timer_remain_second(
						    p->connection->t_routeadv) *
						    1000);
		}
		if (p->password)
			json_object_int_add(json_neigh, "authenticationEnabled",
					    1);

		if (event_is_scheduled(p->connection->t_read))
			json_object_string_add(json_neigh, "readThread", "on");
		else
			json_object_string_add(json_neigh, "readThread", "off");

		if (CHECK_FLAG(p->connection->thread_flags,
			       PEER_THREAD_WRITES_ON))
			json_object_string_add(json_neigh, "writeThread", "on");
		else
			json_object_string_add(json_neigh, "writeThread",
					       "off");
	} else {
		vty_out(vty, "BGP Connect Retry Timer in Seconds: %d\n",
			p->v_connect);
		if (peer_established(p->connection)) {
			vty_out(vty, "Estimated round trip time: %d ms\n",
				p->rtt);
			if (CHECK_FLAG(p->flags, PEER_FLAG_RTT_SHUTDOWN))
				vty_out(vty,
					"Shutdown when RTT > %dms, count > %u\n",
					p->rtt_expected, p->rtt_keepalive_rcv);
		}
		if (event_is_scheduled(p->connection->t_start))
			vty_out(vty, "Next start timer due in %ld seconds\n",
				event_timer_remain_second(
					p->connection->t_start));
		if (event_is_scheduled(p->connection->t_connect))
			vty_out(vty, "Next connect timer due in %ld seconds\n",
				event_timer_remain_second(
					p->connection->t_connect));
		if (event_is_scheduled(p->connection->t_routeadv))
			vty_out(vty,
				"MRAI (interval %u) timer expires in %ld seconds\n",
				p->v_routeadv,
				event_timer_remain_second(
					p->connection->t_routeadv));

		if (p->bfd_config)
			vty_out(vty, "BFD Hold Time (interval %u) timer expires in %ld seconds\n",
				p->bfd_config->hold_time,
				event_timer_remain_second(p->bfd_config->t_hold_timer));

		if (CHECK_FLAG(p->sflags, PEER_STATUS_BFD_STRICT_HOLD))
			vty_out(vty,
				"Incoming connection held until BFD session is up (BFD strict mode)\n");

		if (p->password)
			vty_out(vty, "Peer Authentication Enabled\n");

		vty_out(vty, "Read thread: %s  Write thread: %s  FD used: %d\n",
			p->connection->t_read ? "on" : "off",
			CHECK_FLAG(p->connection->thread_flags,
				   PEER_THREAD_WRITES_ON)
				? "on"
				: "off",
			p->connection->fd);
	}

	if (p->notify.code == BGP_NOTIFY_OPEN_ERR
	    && p->notify.subcode == BGP_NOTIFY_OPEN_UNSUP_CAPBL)
		bgp_capability_vty_out(vty, p, use_json, json_neigh);

	if (!use_json)
		vty_out(vty, "\n");

	/* BFD information. */
	if (p->bfd_config)
		bgp_bfd_show_info(vty, p, json_neigh);

	if (use_json) {
		if (p->conf_if) /* Configured interface name. */
			json_object_object_add(json, p->conf_if, json_neigh);
		else /* Configured IP address. */
			json_object_object_add(json, p->host, json_neigh);
	}
}

static bool match_peer_state(struct peer *bpeer, uint32_t sh_flags)
{
	bool show_estab = CHECK_FLAG(sh_flags, VTY_BGP_PEER_SHOW_STATE_ESTABLISHED_INFO);
	bool show_not_estab = CHECK_FLAG(sh_flags, VTY_BGP_PEER_SHOW_STATE_FAILED_INFO);

	/* show flags for bgp state is not enabled */
	if (!(show_estab || show_not_estab))
		return true;
	/* show flag for bgp state established is enabled and
	 * bgp state is established
	 */
	else if (show_estab && bpeer->connection && peer_established(bpeer->connection))
		return true;
	/* show flag for bgp state failed (not-established)
	 * is enabled and bgp state is not established
	 */
	else if (show_not_estab && bpeer->connection && !peer_established(bpeer->connection))
		return true;

	/* peer state does not match with show flag */
	return false;
}

static int bgp_show_neighbor(struct vty *vty, struct bgp *bgp, enum show_type type,
			     union sockunion *su, const char *conf_if, uint16_t sh_flags,
			     bool use_json, json_object *json)
{
	struct listnode *node, *nnode;
	struct peer *peer;
	int find = 0;
	bool peer_wrong_state = false;
	bool nbr_output = false;
	afi_t afi = AFI_MAX;
	safi_t safi = SAFI_MAX;
	bool is_first = true;
	bool show_brief = ((CHECK_FLAG(sh_flags, VTY_BGP_PEER_SHOW_STATE_ESTABLISHED_INFO) ||
			    CHECK_FLAG(sh_flags, VTY_BGP_PEER_SHOW_STATE_FAILED_INFO) ||
			    CHECK_FLAG(sh_flags, VTY_BGP_PEER_SHOW_BRIEF_INFO)));

	if (type == show_ipv4_peer || type == show_ipv4_all) {
		afi = AFI_IP;
	} else if (type == show_ipv6_peer || type == show_ipv6_all) {
		afi = AFI_IP6;
	}

	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
		if (!peer_is_config_node(peer))
			continue;
		else if ((type == show_all || type == show_ipv4_all || type == show_ipv6_all) &&
			 !match_peer_state(peer, sh_flags))
			continue;
		else if (show_brief && is_first && !use_json) {
			vty_out(vty, BGP_SHOW_NEIGHBORS_BRIEF_HEADER);
			is_first = false;
		}
		switch (type) {
		case show_all:
			bgp_show_peer(vty, peer, sh_flags, use_json, json);
			nbr_output = true;
			break;
		case show_peer:
			if (conf_if) {
				if ((peer->conf_if && strmatch(peer->conf_if, conf_if)) ||
				    (peer->hostname && strmatch(peer->hostname, conf_if))) {
					if (!match_peer_state(peer, sh_flags)) {
						peer_wrong_state = true;
						break;
					}
					find = 1;
					bgp_show_peer(vty, peer, sh_flags, use_json, json);
				}
			} else {
				if (sockunion_same(&peer->connection->su, su)) {
					if (!match_peer_state(peer, sh_flags)) {
						peer_wrong_state = true;
						break;
					}
					find = 1;
					bgp_show_peer(vty, peer, sh_flags, use_json, json);
				}
			}
			break;
		case show_ipv4_peer:
		case show_ipv6_peer: {
			bool matched = false;

			FOREACH_SAFI (safi) {
				if (!peer->afc[afi][safi])
					continue;
				if (conf_if) {
					matched = (peer->conf_if &&
						   strmatch(peer->conf_if, conf_if)) ||
						  (peer->hostname &&
						   strmatch(peer->hostname, conf_if));
				} else {
					matched = sockunion_same(&peer->connection->su, su);
				}
				if (matched) {
					if (!match_peer_state(peer, sh_flags)) {
						peer_wrong_state = true;
						break;
					}
					find = 1;
					bgp_show_peer(vty, peer, sh_flags, use_json, json);
					break;
				}
			}
			break;
		}
		case show_ipv4_all:
		case show_ipv6_all:
			FOREACH_SAFI (safi) {
				if (peer->afc[afi][safi]) {
					bgp_show_peer(vty, peer, sh_flags, use_json, json);
					nbr_output = true;
					break;
				}
			}
			break;
		}
	}

	if ((type == show_peer || type == show_ipv4_peer ||
	     type == show_ipv6_peer) && !find) {
		if (peer_wrong_state) {
			if (use_json)
				json_object_boolean_true_add(json,
							     "bgpNeighborNotInRequestedState");
			else
				vty_out(vty, "%% Neighbor is not in the requested state\n");
		} else {
			if (use_json)
				json_object_boolean_true_add(json, "bgpNoSuchNeighbor");
			else
				vty_out(vty, "%% No such neighbor in this view/vrf\n");
		}
	}

	if (type != show_peer && type != show_ipv4_peer &&
	    type != show_ipv6_peer && !nbr_output && !use_json)
		vty_out(vty, "%% No BGP neighbors found\n");

	if (use_json) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
	} else {
		vty_out(vty, "\n");
	}

	return CMD_SUCCESS;
}

static void bgp_show_all_instances_neighbors_vty(struct vty *vty, enum show_type type,
						 const char *ip_str, uint16_t sh_flags,
						 bool use_json)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;
	union sockunion su;
	json_object *json = NULL;
	int ret, is_first = 1;
	bool nbr_output = false;

	if (use_json)
		vty_out(vty, "{\n");

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		if (CHECK_FLAG(bgp->vrf_flags, BGP_VRF_AUTO))
			continue;

		if (IS_BGP_INSTANCE_HIDDEN(bgp))
			continue;

		nbr_output = true;
		if (use_json) {
			if (!(json = json_object_new_object())) {
				flog_err(
					EC_BGP_JSON_MEM_ERROR,
					"Unable to allocate memory for JSON object");
				vty_out(vty,
					"{\"error\": {\"message:\": \"Unable to allocate memory for JSON object\"}}}\n");
				return;
			}

			json_object_int_add(json, "vrfId",
					    (bgp->vrf_id == VRF_UNKNOWN)
						    ? -1
						    : (int64_t)bgp->vrf_id);
			json_object_string_add(
				json, "vrfName",
				(bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)
					? VRF_DEFAULT_NAME
					: bgp->name);

			if (!is_first)
				vty_out(vty, ",\n");
			else
				is_first = 0;

			vty_out(vty, "\"%s\":",
				(bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)
					? VRF_DEFAULT_NAME
					: bgp->name);
		} else {
			vty_out(vty, "\nInstance %s:\n",
				(bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)
					? VRF_DEFAULT_NAME
					: bgp->name);
		}

		if (!use_json && sh_flags) {
			/* Any special header text for non-JSON */
			if (sh_flags & VTY_BGP_PEER_SHOW_GR_INFO)
				vty_out(vty, "\n%s", SHOW_GR_HEADER);
		}

		if (type == show_peer || type == show_ipv4_peer ||
		    type == show_ipv6_peer) {
			ret = str2sockunion(ip_str, &su);
			if (ret < 0)
				bgp_show_neighbor(vty, bgp, type, NULL, ip_str, sh_flags, use_json,
						  json);
			else
				bgp_show_neighbor(vty, bgp, type, &su, NULL, sh_flags, use_json,
						  json);
		} else {
			bgp_show_neighbor(vty, bgp, type, NULL, NULL, sh_flags, use_json, json);
		}
		json_object_free(json);
		json = NULL;
	}

	if (use_json)
		vty_out(vty, "}\n");
	else if (!nbr_output)
		vty_out(vty, "%% BGP instance not found\n");
}

static int bgp_show_neighbor_vty(struct vty *vty, const char *name, enum show_type type,
				 const char *ip_str, uint16_t sh_flags, bool use_json)
{
	int ret;
	struct bgp *bgp;
	union sockunion su;
	json_object *json = NULL;

	if (name) {
		if (strmatch(name, "all")) {
			bgp_show_all_instances_neighbors_vty(vty, type, ip_str, sh_flags, use_json);
			return CMD_SUCCESS;
		} else {
			bgp = bgp_lookup_by_name(name);
			if (!bgp) {
				if (use_json) {
					json = json_object_new_object();
					vty_json(vty, json);
				} else
					vty_out(vty,
						"%% BGP instance not found\n");

				return CMD_WARNING;
			}
		}
	} else {
		bgp = bgp_get_default();
	}

	if (bgp) {
		if (!use_json && sh_flags) {
			/* Any special header text for non-JSON */
			if (sh_flags & VTY_BGP_PEER_SHOW_GR_INFO)
				vty_out(vty, "\n%s", SHOW_GR_HEADER);
		}
		json = json_object_new_object();
		if (ip_str) {
			ret = str2sockunion(ip_str, &su);
			if (ret < 0)
				bgp_show_neighbor(vty, bgp, type, NULL, ip_str, sh_flags, use_json,
						  json);
			else
				bgp_show_neighbor(vty, bgp, type, &su, NULL, sh_flags, use_json,
						  json);
		} else {
			bgp_show_neighbor(vty, bgp, type, NULL, NULL, sh_flags, use_json, json);
		}
		json_object_free(json);
	} else {
		if (use_json)
			vty_out(vty, "{}\n");
		else
			vty_out(vty, "%% BGP instance not found\n");
	}

	return CMD_SUCCESS;
}

/* "show [ip] bgp neighbors" commands.  */
DEFPY(show_ip_bgp_neighbors, show_ip_bgp_neighbors_cmd,
      "show [ip] bgp [<view|vrf> VIEWVRFNAME] [<ipv4|ipv6>] neighbors [<A.B.C.D|X:X::X:X|WORD>] [graceful-restart] [json$uj [brief$brief [established|failed]]]",
      SHOW_STR IP_STR BGP_STR BGP_INSTANCE_HELP_STR BGP_AF_STR BGP_AF_STR
      "Detailed information on TCP and BGP neighbor connections\n"
      "Neighbor to display information about\n"
      "Neighbor to display information about\n"
      "Neighbor on BGP configured interface\n"
      "Neighbor graceful restart information\n"
      JSON_STR
      "Brief information on BGP neighbors (JSON output)\n"
      "Display only neighbors in Established state\n"
      "Display only neighbors not in Established state\n")
{
	char *vrf = NULL;
	char *sh_arg = NULL;
	enum show_type sh_type;
	afi_t afi = AFI_MAX;

	bool use_json = !!uj;
	int idx = 0;
	int gr_idx = 0;
	bool show_gr = false;
	uint16_t peer_show_flags = 0;

	/* [<vrf> VIEWVRFNAME] */
	if (argv_find(argv, argc, "vrf", &idx)) {
		vrf = argv[idx + 1]->arg;
		if (vrf && strmatch(vrf, VRF_DEFAULT_NAME))
			vrf = NULL;
	} else if (argv_find(argv, argc, "view", &idx))
		/* [<view> VIEWVRFNAME] */
		vrf = argv[idx + 1]->arg;

	idx++;

	if (argv_find(argv, argc, "graceful-restart", &gr_idx))
		show_gr = true;

	/* If operator wants to see GR information for a neighbor or all
	 * neighbors, the AFI negotiation is ignored.
	 */
	if (show_gr)
		sh_type = show_all;
	else {
		if (argv_find(argv, argc, "ipv4", &idx)) {
			sh_type = show_ipv4_all;
			afi = AFI_IP;
		} else if (argv_find(argv, argc, "ipv6", &idx)) {
			sh_type = show_ipv6_all;
			afi = AFI_IP6;
		} else {
			sh_type = show_all;
		}
	}

	if (argv_find(argv, argc, "A.B.C.D", &idx)
	    || argv_find(argv, argc, "X:X::X:X", &idx)
	    || argv_find(argv, argc, "WORD", &idx)) {
		sh_type = show_peer;
		sh_arg = argv[idx]->arg;
	}

	if (!show_gr) {
		if (sh_type == show_peer && afi == AFI_IP)
			sh_type = show_ipv4_peer;
		else if (sh_type == show_peer && afi == AFI_IP6)
			sh_type = show_ipv6_peer;
	}

	if (show_gr)
		peer_show_flags |= VTY_BGP_PEER_SHOW_GR_INFO;
	else if (use_json && brief) {
		SET_FLAG(peer_show_flags, VTY_BGP_PEER_SHOW_BRIEF_INFO);
		if (argv_find(argv, argc, "established", &idx))
			SET_FLAG(peer_show_flags, VTY_BGP_PEER_SHOW_STATE_ESTABLISHED_INFO);
		else if (argv_find(argv, argc, "failed", &idx))
			SET_FLAG(peer_show_flags, VTY_BGP_PEER_SHOW_STATE_FAILED_INFO);
	}

	return bgp_show_neighbor_vty(vty, vrf, sh_type, sh_arg, peer_show_flags, use_json);
}

/* "show [ip] bgp neighbors <peer> orf-prefix-list" command */
DEFPY (show_bgp_neighbor_orf_prefix_list,
       show_bgp_neighbor_orf_prefix_list_cmd,
       "show [ip] bgp [<view|vrf> VIEWVRFNAME] ["BGP_AFI_CMD_STR" ["BGP_SAFI_WITH_LABEL_CMD_STR"]] neighbors <A.B.C.D|X:X::X:X|WORD>$neighbor orf-prefix-list [json$uj]",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       BGP_AFI_HELP_STR
       BGP_SAFI_WITH_LABEL_HELP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on BGP configured interface\n"
       "Display the ORF prefix-list received from this neighbor\n"
       JSON_STR)
{
	int idx = 0;
	struct bgp *bgp = NULL;
	struct peer *peer;
	afi_t afi = AFI_IP;
	safi_t safi = SAFI_UNICAST;
	char orf_name[BUFSIZ];
	bool use_json = !!uj;

	bgp_vty_find_and_parse_afi_safi_bgp(vty, argv, argc, &idx, &afi, &safi, &bgp, use_json);
	if (!idx)
		return CMD_WARNING;

	peer = peer_lookup_in_view(vty, bgp, neighbor, use_json);
	if (!peer)
		return CMD_WARNING;

	peer_orf_plist_name(peer, afi, safi, orf_name, sizeof(orf_name));
	if (!prefix_bgp_show_prefix_list(NULL, afi, orf_name, use_json)) {
		if (use_json)
			vty_out(vty, "{}\n");
		else
			vty_out(vty, "%% No ORF prefix-list received from %s\n", neighbor);
		return CMD_SUCCESS;
	}

	prefix_bgp_show_prefix_list(vty, afi, orf_name, use_json);
	return CMD_SUCCESS;
}

/* Show BGP's AS paths internal data.  There are both `show [ip] bgp
   paths' and `show ip mbgp paths'.  Those functions results are the
   same.*/
DEFUN (show_ip_bgp_paths,
       show_ip_bgp_paths_cmd,
       "show [ip] bgp ["BGP_SAFI_CMD_STR"] paths",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_SAFI_HELP_STR
       "Path information\n")
{
	vty_out(vty, "Address Refcnt Path\n");
	aspath_print_all_vty(vty);
	return CMD_SUCCESS;
}

#include "hash.h"

static void community_show_all_iterator(struct hash_bucket *bucket,
					struct vty *vty)
{
	struct community *com;

	com = (struct community *)bucket->data;
	vty_out(vty, "[%p] (%ld) %s\n", (void *)com, com->refcnt, community_str(com, false));
}

/* Show BGP's community internal data. */
DEFUN (show_ip_bgp_community_info,
       show_ip_bgp_community_info_cmd,
       "show [ip] bgp community-info",
       SHOW_STR
       IP_STR
       BGP_STR
       "List all bgp community information\n")
{
	vty_out(vty, "Address Refcnt Community\n");

	hash_iterate(community_hash(),
		     (void (*)(struct hash_bucket *,
			       void *))community_show_all_iterator,
		     vty);

	return CMD_SUCCESS;
}

static void lcommunity_show_all_iterator(struct hash_bucket *bucket,
					 struct vty *vty)
{
	struct lcommunity *lcom;

	lcom = (struct lcommunity *)bucket->data;
	vty_out(vty, "[%p] (%ld) %s\n", (void *)lcom, lcom->refcnt, lcommunity_str(lcom, false));
}

/* Show BGP's community internal data. */
DEFUN (show_ip_bgp_lcommunity_info,
       show_ip_bgp_lcommunity_info_cmd,
       "show ip bgp large-community-info",
       SHOW_STR
       IP_STR
       BGP_STR
       "List all bgp large-community information\n")
{
	vty_out(vty, "Address Refcnt Large-community\n");

	hash_iterate(lcommunity_hash(),
		     (void (*)(struct hash_bucket *,
			       void *))lcommunity_show_all_iterator,
		     vty);

	return CMD_SUCCESS;
}

DEFPY (show_ip_bgp_attr_info,
       show_ip_bgp_attr_info_cmd,
       "show [ip] bgp attribute-info [summary$summary]",
       SHOW_STR
       IP_STR
       BGP_STR
       "List all bgp attribute information\n"
       "Display summary of BGP attributes\n")
{
	attr_show_all(vty, summary);
	return CMD_SUCCESS;
}

static int bgp_show_route_leak_vty(struct vty *vty, const char *name,
				   afi_t afi, safi_t safi,
				   bool use_json, json_object *json)
{
	struct bgp *bgp;
	struct listnode *node;
	char *vname;
	char *ecom_str;
	enum vpn_policy_direction dir;

	if (json) {
		json_object *json_import_vrfs = NULL;
		json_object *json_export_vrfs = NULL;

		bgp = name ? bgp_lookup_by_name(name) : bgp_get_default();

		if (!bgp) {
			vty_json(vty, json);

			return CMD_WARNING;
		}

		/* Provide context for the block */
		json_object_string_add(json, "vrf", name ? name : "default");
		json_object_string_add(json, "afiSafi",
				       get_afi_safi_str(afi, safi, true));

		if (!CHECK_FLAG(bgp->af_flags[afi][safi],
				BGP_CONFIG_VRF_TO_VRF_IMPORT)) {
			json_object_string_add(json, "importFromVrfs", "none");
			json_object_string_add(json, "importRts", "none");
		} else {
			json_import_vrfs = json_object_new_array();

			for (ALL_LIST_ELEMENTS_RO(
						bgp->vpn_policy[afi].import_vrf,
						node, vname))
				json_object_array_add(json_import_vrfs,
						json_object_new_string(vname));

			json_object_object_add(json, "importFromVrfs",
						       json_import_vrfs);
			dir = BGP_VPN_POLICY_DIR_FROMVPN;
			if (bgp->vpn_policy[afi].rtlist[dir]) {
				ecom_str = ecommunity_ecom2str(
					bgp->vpn_policy[afi].rtlist[dir],
					ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
				json_object_string_add(json, "importRts",
						       ecom_str);
				XFREE(MTYPE_ECOMMUNITY_STR, ecom_str);
			} else
				json_object_string_add(json, "importRts",
						       "none");
		}

		if (!CHECK_FLAG(bgp->af_flags[afi][safi],
				BGP_CONFIG_VRF_TO_VRF_EXPORT)) {
			json_object_string_add(json, "exportToVrfs", "none");
			json_object_string_add(json, "routeDistinguisher",
					       "none");
			json_object_string_add(json, "exportRts", "none");
		} else {
			json_export_vrfs = json_object_new_array();

			for (ALL_LIST_ELEMENTS_RO(
						bgp->vpn_policy[afi].export_vrf,
						node, vname))
				json_object_array_add(json_export_vrfs,
						json_object_new_string(vname));
			json_object_object_add(json, "exportToVrfs",
					       json_export_vrfs);
			json_object_string_addf(json, "routeDistinguisher",
						BGP_RD_AS_FORMAT(bgp->asnotation),
						&bgp->vpn_policy[afi].tovpn_rd);
			dir = BGP_VPN_POLICY_DIR_TOVPN;
			if (bgp->vpn_policy[afi].rtlist[dir]) {
				ecom_str = ecommunity_ecom2str(
					       bgp->vpn_policy[afi].rtlist[dir],
					       ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
				json_object_string_add(json, "exportRts",
						       ecom_str);
				XFREE(MTYPE_ECOMMUNITY_STR, ecom_str);
			} else
				json_object_string_add(json, "exportRts",
						       "none");
		}

		if (use_json) {
			vty_json(vty, json);
		}
	} else {
		bgp = name ? bgp_lookup_by_name(name) : bgp_get_default();

		if (!bgp) {
			vty_out(vty, "%% No such BGP instance exist\n");
			return CMD_WARNING;
		}

		if (!CHECK_FLAG(bgp->af_flags[afi][safi],
				BGP_CONFIG_VRF_TO_VRF_IMPORT))
			vty_out(vty,
		     "This VRF is not importing %s routes from any other VRF\n",
		      get_afi_safi_str(afi, safi, false));
		else {
			vty_out(vty,
		   "This VRF is importing %s routes from the following VRFs:\n",
		    get_afi_safi_str(afi, safi, false));

			for (ALL_LIST_ELEMENTS_RO(
						bgp->vpn_policy[afi].import_vrf,
						node, vname))
				vty_out(vty, "  %s\n", vname);

			dir = BGP_VPN_POLICY_DIR_FROMVPN;
			ecom_str = NULL;
			if (bgp->vpn_policy[afi].rtlist[dir]) {
				ecom_str = ecommunity_ecom2str(
					       bgp->vpn_policy[afi].rtlist[dir],
					       ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
				vty_out(vty, "Import RT(s): %s\n", ecom_str);

				XFREE(MTYPE_ECOMMUNITY_STR, ecom_str);
			} else
				vty_out(vty, "Import RT(s):\n");
		}

		if (!CHECK_FLAG(bgp->af_flags[afi][safi],
				BGP_CONFIG_VRF_TO_VRF_EXPORT))
			vty_out(vty,
		       "This VRF is not exporting %s routes to any other VRF\n",
			get_afi_safi_str(afi, safi, false));
		else {
			vty_out(vty,
		       "This VRF is exporting %s routes to the following VRFs:\n",
			get_afi_safi_str(afi, safi, false));

			for (ALL_LIST_ELEMENTS_RO(
						bgp->vpn_policy[afi].export_vrf,
						node, vname))
				vty_out(vty, "  %s\n", vname);

			vty_out(vty, "RD: ");
			vty_out(vty, BGP_RD_AS_FORMAT(bgp->asnotation),
				&bgp->vpn_policy[afi].tovpn_rd);
			vty_out(vty, "\n");

			dir = BGP_VPN_POLICY_DIR_TOVPN;
			if (bgp->vpn_policy[afi].rtlist[dir]) {
				ecom_str = ecommunity_ecom2str(
					bgp->vpn_policy[afi].rtlist[dir],
					ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
				vty_out(vty, "Export RT: %s\n", ecom_str);
				XFREE(MTYPE_ECOMMUNITY_STR, ecom_str);
			} else
				vty_out(vty, "Import RT(s):\n");
		}
	}

	return CMD_SUCCESS;
}

static int bgp_show_all_instance_route_leak_vty(struct vty *vty, afi_t afi,
						safi_t safi, bool use_json)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;
	char *vrf_name = NULL;
	json_object *json = NULL;
	json_object *json_vrf = NULL;
	json_object *json_vrfs = NULL;

	if (use_json) {
		json = json_object_new_object();
		json_vrfs = json_object_new_object();
	}

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {

		if (bgp->inst_type != BGP_INSTANCE_TYPE_DEFAULT)
			vrf_name = bgp->name;

		if (CHECK_FLAG(bgp->vrf_flags, BGP_VRF_AUTO))
			continue;

		if (use_json) {
			json_vrf = json_object_new_object();
		} else {
			vty_out(vty, "\nInstance %s:\n",
				(bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)
				? VRF_DEFAULT_NAME : bgp->name);
		}
		bgp_show_route_leak_vty(vty, vrf_name, afi, safi, 0, json_vrf);
		if (use_json) {
			if (bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)
				json_object_object_add(json_vrfs,
						VRF_DEFAULT_NAME, json_vrf);
			else
				json_object_object_add(json_vrfs, vrf_name,
						       json_vrf);
		}
	}

	if (use_json) {
		json_object_object_add(json, "vrfs", json_vrfs);
		vty_json(vty, json);
	}

	return CMD_SUCCESS;
}

/* "show [ip] bgp route-leak" command.  */
DEFUN (show_ip_bgp_route_leak,
	show_ip_bgp_route_leak_cmd,
	"show [ip] bgp [<view|vrf> VIEWVRFNAME] ["BGP_AFI_CMD_STR" ["BGP_SAFI_CMD_STR"]] route-leak  [json]",
	SHOW_STR
	IP_STR
	BGP_STR
	BGP_INSTANCE_HELP_STR
	BGP_AFI_HELP_STR
	BGP_SAFI_HELP_STR
	"Route leaking information\n"
	JSON_STR)
{
	char *vrf = NULL;
	afi_t afi = AFI_MAX;
	safi_t safi = SAFI_MAX;

	bool uj = use_json(argc, argv);
	int idx = 0;
	json_object *json = NULL;

	/* show [ip] bgp */
	if (argv_find(argv, argc, "ip", &idx)) {
		afi = AFI_IP;
		safi = SAFI_UNICAST;
	}
	/* [vrf VIEWVRFNAME] */
	if (argv_find(argv, argc, "view", &idx)) {
		vty_out(vty,
			"%% This command is not applicable to BGP views\n");
		return CMD_WARNING;
	}

	if (argv_find(argv, argc, "vrf", &idx)) {
		vrf = argv[idx + 1]->arg;
		if (vrf && strmatch(vrf, VRF_DEFAULT_NAME))
			vrf = NULL;
	}
	/* ["BGP_AFI_CMD_STR" ["BGP_SAFI_CMD_STR"]] */
	if (argv_find_and_parse_afi(argv, argc, &idx, &afi))
		argv_find_and_parse_safi(argv, argc, &idx, &safi);

	if (!((afi == AFI_IP || afi == AFI_IP6) && safi == SAFI_UNICAST)) {
		vty_out(vty,
			"%% This command is applicable only for unicast ipv4|ipv6\n");
		return CMD_WARNING;
	}

	if (vrf && strmatch(vrf, "all"))
		return bgp_show_all_instance_route_leak_vty(vty, afi, safi, uj);

	if (uj)
		json = json_object_new_object();

	return bgp_show_route_leak_vty(vty, vrf, afi, safi, uj, json);
}

static void bgp_show_all_instances_updgrps_vty(struct vty *vty, afi_t afi,
					       safi_t safi, bool uj)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		if (CHECK_FLAG(bgp->vrf_flags, BGP_VRF_AUTO))
			continue;

		if (IS_BGP_INSTANCE_HIDDEN(bgp))
			continue;

		if (!uj)
			vty_out(vty, "\nInstance %s:\n",
				(bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT)
					? VRF_DEFAULT_NAME
					: bgp->name);

		update_group_show(bgp, afi, safi, vty, 0, uj);
	}
}

static int bgp_show_update_groups(struct vty *vty, const char *name, int afi,
				  int safi, uint64_t subgrp_id, bool uj)
{
	struct bgp *bgp;

	if (name) {
		if (strmatch(name, "all")) {
			bgp_show_all_instances_updgrps_vty(vty, afi, safi, uj);
			return CMD_SUCCESS;
		} else {
			bgp = bgp_lookup_by_name(name);
		}
	} else {
		bgp = bgp_get_default();
	}

	if (bgp)
		update_group_show(bgp, afi, safi, vty, subgrp_id, uj);
	return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_updgrps,
       show_ip_bgp_updgrps_cmd,
       "show [ip] bgp [<view|vrf> VIEWVRFNAME] ["BGP_AFI_CMD_STR" ["BGP_SAFI_WITH_LABEL_CMD_STR"]] update-groups [SUBGROUP-ID] [json]",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       BGP_AFI_HELP_STR
       BGP_SAFI_WITH_LABEL_HELP_STR
       "Detailed info about dynamic update groups\n"
       "Specific subgroup to display detailed info for\n"
       JSON_STR)
{
	char *vrf = NULL;
	afi_t afi = AFI_IP6;
	safi_t safi = SAFI_UNICAST;
	uint64_t subgrp_id = 0;

	int idx = 0;

	bool uj = use_json(argc, argv);

	/* show [ip] bgp */
	if (argv_find(argv, argc, "ip", &idx))
		afi = AFI_IP;
	/* [<vrf> VIEWVRFNAME] */
	if (argv_find(argv, argc, "vrf", &idx)) {
		vrf = argv[idx + 1]->arg;
		if (vrf && strmatch(vrf, VRF_DEFAULT_NAME))
			vrf = NULL;
	} else if (argv_find(argv, argc, "view", &idx))
		/* [<view> VIEWVRFNAME] */
		vrf = argv[idx + 1]->arg;
	/* ["BGP_AFI_CMD_STR" ["BGP_SAFI_CMD_STR"]] */
	if (argv_find_and_parse_afi(argv, argc, &idx, &afi)) {
		argv_find_and_parse_safi(argv, argc, &idx, &safi);
	}

	/* get subgroup id, if provided */
	idx = argc - 1;
	if (argv[idx]->type == VARIABLE_TKN)
		subgrp_id = strtoull(argv[idx]->arg, NULL, 10);

	return (bgp_show_update_groups(vty, vrf, afi, safi, subgrp_id, uj));
}

DEFUN (show_bgp_instance_all_ipv6_updgrps,
       show_bgp_instance_all_ipv6_updgrps_cmd,
       "show [ip] bgp <view|vrf> all update-groups [json]",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_ALL_HELP_STR
       "Detailed info about dynamic update groups\n"
       JSON_STR)
{
	bool uj = use_json(argc, argv);

	bgp_show_all_instances_updgrps_vty(vty, AFI_IP6, SAFI_UNICAST, uj);
	return CMD_SUCCESS;
}

DEFPY(show_bgp_l2vpn_evpn_updgrps,
      show_bgp_l2vpn_evpn_updgrps_cmd,
      "show [ip] bgp l2vpn evpn update-groups [subgroup-id (1-1000)$subgrpid] [json$json]",
      SHOW_STR
      IP_STR
      BGP_STR
      "l2vpn address family\n"
      "evpn sub-address family\n"
      "Detailed info about dynamic update groups\n"
      "Specific subgroup to display detailed info\n"
      "Subgroup identifier\n"
      JSON_STR)
{
	char *vrf = NULL;
	bool uj = !!json;

	bgp_show_update_groups(vty, vrf, AFI_L2VPN, SAFI_EVPN, subgrpid, uj);
	return CMD_SUCCESS;
}

DEFUN (show_bgp_updgrps_stats,
       show_bgp_updgrps_stats_cmd,
       "show [ip] bgp update-groups statistics",
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed info about dynamic update groups\n"
       "Statistics\n")
{
	struct bgp *bgp;

	bgp = bgp_get_default();
	if (bgp && !IS_BGP_INSTANCE_HIDDEN(bgp))
		update_group_show_stats(bgp, vty);

	return CMD_SUCCESS;
}

DEFUN (show_bgp_instance_updgrps_stats,
       show_bgp_instance_updgrps_stats_cmd,
       "show [ip] bgp <view|vrf> VIEWVRFNAME update-groups statistics",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       "Detailed info about dynamic update groups\n"
       "Statistics\n")
{
	int idx_word = 3;
	struct bgp *bgp;

	bgp = bgp_lookup_by_name(argv[idx_word]->arg);
	if (bgp)
		update_group_show_stats(bgp, vty);

	return CMD_SUCCESS;
}

static void show_bgp_updgrps_adj_info_aux(struct vty *vty, const char *name,
					  afi_t afi, safi_t safi,
					  const char *what, uint64_t subgrp_id)
{
	struct bgp *bgp;

	if (name)
		bgp = bgp_lookup_by_name(name);
	else
		bgp = bgp_get_default();

	if (bgp) {
		if (!strcmp(what, "advertise-queue"))
			update_group_show_adj_queue(bgp, afi, safi, vty,
						    subgrp_id);
		else if (!strcmp(what, "advertised-routes"))
			update_group_show_advertised(bgp, afi, safi, vty,
						     subgrp_id);
		else if (!strcmp(what, "packet-queue"))
			update_group_show_packet_queue(bgp, afi, safi, vty,
						       subgrp_id);
	}
}

DEFPY(show_ip_bgp_instance_updgrps_adj_s,
      show_ip_bgp_instance_updgrps_adj_s_cmd,
      "show [ip]$ip bgp [<view|vrf> VIEWVRFNAME$vrf] [<ipv4|ipv6>$afi <unicast|multicast|vpn>$safi] update-groups [SUBGROUP-ID]$sgid <advertise-queue|advertised-routes|packet-queue>$rtq",
      SHOW_STR IP_STR BGP_STR BGP_INSTANCE_HELP_STR BGP_AFI_HELP_STR
	      BGP_SAFI_HELP_STR
      "Detailed info about dynamic update groups\n"
      "Specific subgroup to display info for\n"
      "Advertisement queue\n"
      "Announced routes\n"
      "Packet queue\n")
{
	uint64_t subgrp_id = 0;
	afi_t afiz;
	safi_t safiz;
	if (sgid)
		subgrp_id = strtoull(sgid, NULL, 10);

	if (!ip && !afi)
		afiz = AFI_IP6;
	if (!ip && afi)
		afiz = bgp_vty_afi_from_str(afi);
	if (ip && !afi)
		afiz = AFI_IP;
	if (ip && afi) {
		afiz = bgp_vty_afi_from_str(afi);
		if (afiz != AFI_IP)
			vty_out(vty,
				"%% Cannot specify both 'ip' and 'ipv6'\n");
		return CMD_WARNING;
	}

	safiz = safi ? bgp_vty_safi_from_str(safi) : SAFI_UNICAST;

	show_bgp_updgrps_adj_info_aux(vty, vrf, afiz, safiz, rtq, subgrp_id);
	return CMD_SUCCESS;
}

static int bgp_show_one_peer_group(struct vty *vty, struct peer_group *group,
				   json_object *json)
{
	struct listnode *node, *nnode;
	struct prefix *range;
	struct peer *conf;
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	const char *peer_status;
	int lr_count;
	int dynamic;
	bool af_cfgd = false;
	json_object *json_peer_group = NULL;
	json_object *json_peer_group_afc = NULL;
	json_object *json_peer_group_members = NULL;
	json_object *json_peer_group_dynamic = NULL;
	json_object *json_peer_group_dynamic_af = NULL;
	json_object *json_peer_group_ranges = NULL;
	uint16_t member_count = 0;

	conf = group->conf;

	if (json) {
		json_peer_group = json_object_new_object();
		json_peer_group_afc = json_object_new_array();
	}

	if (conf->as_type == AS_SPECIFIED || conf->as_type == AS_EXTERNAL) {
		if (json)
			asn_asn2json(json_peer_group, "remoteAs", conf->as,
				     bgp_get_asnotation(conf->bgp));
		else {
			vty_out(vty, "\nBGP peer-group %s, remote AS ",
				group->name);
			vty_out(vty, ASN_FORMAT(bgp_get_asnotation(conf->bgp)),
				&conf->as);
			vty_out(vty, "\n");
		}
	} else if (CHECK_FLAG(conf->as_type, AS_INTERNAL)) {
		if (json)
			asn_asn2json(json_peer_group, "remoteAs", group->bgp->as,
				     group->bgp->asnotation);
		else
			vty_out(vty, "\nBGP peer-group %s, remote AS %s\n",
				group->name, group->bgp->as_pretty);
	} else {
		if (!json)
			vty_out(vty, "\nBGP peer-group %s\n", group->name);
	}

	if (CHECK_FLAG(conf->as_type, AS_AUTO)) {
		if (json)
			json_object_string_add(json_peer_group, "type", "auto");
		else
			vty_out(vty, "  Peer-group type is auto\n");
	} else if ((group->bgp->as == conf->as) ||
		   CHECK_FLAG(conf->as_type, AS_INTERNAL)) {
		if (json)
			json_object_string_add(json_peer_group, "type",
					       "internal");
		else
			vty_out(vty, "  Peer-group type is internal\n");
	} else {
		if (json)
			json_object_string_add(json_peer_group, "type",
					       "external");
		else
			vty_out(vty, "  Peer-group type is external\n");
	}

	/* Display AFs configured. */
	if (!json)
		vty_out(vty, "  Configured address-families:");

	FOREACH_AFI_SAFI (afi, safi) {
		if (conf->afc[afi][safi]) {
			af_cfgd = true;
			if (json)
				json_object_array_add(
					json_peer_group_afc,
					json_object_new_string(get_afi_safi_str(
						afi, safi, false)));
			else
				vty_out(vty, " %s;",
					get_afi_safi_str(afi, safi, false));
		}
	}

	if (json) {
		json_object_object_add(json_peer_group,
				       "addressFamiliesConfigured",
				       json_peer_group_afc);
	} else {
		if (!af_cfgd)
			vty_out(vty, " none\n");
		else
			vty_out(vty, "\n");
	}

	/* Display listen ranges (for dynamic neighbors), if any */
	for (afi = AFI_IP; afi < AFI_MAX; afi++) {
		lr_count = listcount(group->listen_range[afi]);
		if (lr_count) {
			if (json) {
				if (!json_peer_group_dynamic)
					json_peer_group_dynamic =
						json_object_new_object();

				json_peer_group_dynamic_af =
					json_object_new_object();
				json_peer_group_ranges =
					json_object_new_array();
				json_object_int_add(json_peer_group_dynamic_af,
						    "count", lr_count);
			} else {
				vty_out(vty, "  %d %s listen range(s)\n",
					lr_count, afi2str(afi));
			}

			for (ALL_LIST_ELEMENTS(group->listen_range[afi], node,
					       nnode, range)) {
				if (json) {
					char buf[BUFSIZ];

					snprintfrr(buf, sizeof(buf), "%pFX",
						   range);

					json_object_array_add(
						json_peer_group_ranges,
						json_object_new_string(buf));
				} else {
					vty_out(vty, "    %pFX\n", range);
				}
			}

			if (json) {
				json_object_object_add(
					json_peer_group_dynamic_af, "ranges",
					json_peer_group_ranges);

				json_object_object_add(
					json_peer_group_dynamic, afi2str(afi),
					json_peer_group_dynamic_af);
			}
		}
	}

	if (json_peer_group_dynamic)
		json_object_object_add(json_peer_group, "dynamicRanges",
				       json_peer_group_dynamic);

	/* Display group members and their status */
	if (listcount(group->peer)) {
		if (json)
			json_peer_group_members = json_object_new_object();
		else
			vty_out(vty, "  Peer-group members:\n");
		for (ALL_LIST_ELEMENTS(group->peer, node, nnode, peer)) {
			if (CHECK_FLAG(peer->flags, PEER_FLAG_SHUTDOWN)
			    || CHECK_FLAG(peer->bgp->flags, BGP_FLAG_SHUTDOWN))
				peer_status = "Idle (Admin)";
			else if (CHECK_FLAG(peer->sflags,
					    PEER_STATUS_PREFIX_OVERFLOW))
				peer_status = "Idle (PfxCt)";
			else
				peer_status =
					lookup_msg(bgp_status_msg,
						   peer->connection->status,
						   NULL);

			dynamic = peer_dynamic_neighbor(peer);

			if (json) {
				json_object *json_peer_group_member =
					json_object_new_object();

				json_object_string_add(json_peer_group_member,
						       "status", peer_status);

				if (dynamic)
					json_object_boolean_true_add(
						json_peer_group_member,
						"dynamic");

				json_object_object_add(json_peer_group_members,
						       peer->host,
						       json_peer_group_member);
			} else {
				vty_out(vty, "    %s %s %s \n", peer->host,
					dynamic ? "(dynamic)" : "",
					peer_status);
			}
			member_count++;
		}
	}

	if (json) {
		json_object_int_add(json_peer_group, "memberCount", member_count);
		if (member_count)
			json_object_object_add(json_peer_group, "members", json_peer_group_members);
	}

	if (json)
		json_object_object_add(json, group->name, json_peer_group);

	return CMD_SUCCESS;
}

static int bgp_show_peer_group_vty(struct vty *vty, const char *name,
				   const char *group_name, bool uj)
{
	struct bgp *bgp;
	struct listnode *node, *nnode;
	struct peer_group *group;
	bool found = false;
	json_object *json = NULL;

	if (uj)
		json = json_object_new_object();

	bgp = name ? bgp_lookup_by_name(name) : bgp_get_default();

	if (!bgp) {
		if (uj)
			vty_json(vty, json);
		else
			vty_out(vty, "%% BGP instance not found\n");

		return CMD_WARNING;
	}

	for (ALL_LIST_ELEMENTS(bgp->group, node, nnode, group)) {
		if (group_name) {
			if (strmatch(group->name, group_name)) {
				bgp_show_one_peer_group(vty, group, json);
				found = true;
				break;
			}
		} else {
			bgp_show_one_peer_group(vty, group, json);
		}
	}

	if (group_name && !found && !uj)
		vty_out(vty, "%% No such peer-group\n");

	if (uj)
		vty_json(vty, json);

	return CMD_SUCCESS;
}

DEFUN(show_ip_bgp_peer_groups, show_ip_bgp_peer_groups_cmd,
      "show [ip] bgp [<view|vrf> VIEWVRFNAME] peer-group [PGNAME] [json]",
      SHOW_STR IP_STR BGP_STR BGP_INSTANCE_HELP_STR
      "Detailed information on BGP peer groups\n"
      "Peer group name\n" JSON_STR)
{
	char *vrf, *pg;
	int idx = 0;
	bool uj = use_json(argc, argv);

	vrf = argv_find(argv, argc, "VIEWVRFNAME", &idx) ? argv[idx]->arg
							 : NULL;
	pg = argv_find(argv, argc, "PGNAME", &idx) ? argv[idx]->arg : NULL;

	return bgp_show_peer_group_vty(vty, vrf, pg, uj);
}


/* Redistribute VTY commands.  */

/* peer-group helpers for config-write */

bool peergroup_flag_check(struct peer *peer, uint64_t flag)
{
	if (!peer_group_active(peer)) {
		if (CHECK_FLAG(peer->flags_invert, flag))
			return !CHECK_FLAG(peer->flags, flag);
		else
			return !!CHECK_FLAG(peer->flags, flag);
	}

	return !!CHECK_FLAG(peer->flags_override, flag);
}

bool peergroup_af_flag_check(struct peer *peer, afi_t afi, safi_t safi,
			     uint64_t flag)
{
	if (!peer_group_active(peer)) {
		if (CHECK_FLAG(peer->af_flags_invert[afi][safi], flag))
			return !peer_af_flag_check(peer, afi, safi, flag);
		else
			return peer_af_flag_check(peer, afi, safi, flag);
	}

	return !!CHECK_FLAG(peer->af_flags_override[afi][safi], flag);
}

int bgp_config_write(struct vty *vty)
{
	struct bgp *bgp;
	struct listnode *mnode, *mnnode;
	const struct lyd_node *daemon_dnode;

	/* Daemon-wide CONFIG_NODE knobs (/frr-bgp:bgp-daemon). */
	vty_out(vty, "!\n");
	daemon_dnode = yang_dnode_get(running_config->dnode, "/frr-bgp:bgp-daemon");
	if (daemon_dnode)
		nb_cli_show_dnode_cmds(vty, daemon_dnode, false);
	if (bgp_option_check(BGP_OPT_NO_FIB) &&
	    !(daemon_dnode && yang_dnode_exists(daemon_dnode, "./no-rib") &&
	      yang_dnode_get_bool(daemon_dnode, "./no-rib")))
		vty_out(vty, "bgp no-rib\n");
	vty_out(vty, "!\n");

	/*
	 * Per-instance dump via YANG cli_show. Peer AF knobs are injected
	 * inside address-family frames; shutdown leaves dump after peers.
	 * BMP is covered by global/bmp-config cli_show (no hook_call).
	 */
	for (ALL_LIST_ELEMENTS(bm->bgp, mnode, mnnode, bgp)) {
		if (CHECK_FLAG(bgp->vrf_flags, BGP_VRF_AUTO))
			continue;
		if (IS_BGP_INSTANCE_HIDDEN(bgp))
			continue;
		bgp_nb_cli_show_instance_bgp(vty, bgp);
	}
	return 0;
}

/* BGP node structure. */
static struct cmd_node bgp_node = {
	.name = "bgp",
	.node = BGP_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(config-router)# ",
	.config_write = bgp_config_write,
};

static struct cmd_node bgp_ipv4_unicast_node = {
	.name = "bgp ipv4 unicast",
	.node = BGP_IPV4_NODE,
	.parent_node = BGP_NODE,
	.prompt = "%s(config-router-af)# ",
	.no_xpath = true,
};

static struct cmd_node bgp_ipv4_multicast_node = {
	.name = "bgp ipv4 multicast",
	.node = BGP_IPV4M_NODE,
	.parent_node = BGP_NODE,
	.prompt = "%s(config-router-af)# ",
	.no_xpath = true,
};

static struct cmd_node bgp_ipv4_labeled_unicast_node = {
	.name = "bgp ipv4 labeled unicast",
	.node = BGP_IPV4L_NODE,
	.parent_node = BGP_NODE,
	.prompt = "%s(config-router-af)# ",
	.no_xpath = true,
};

static struct cmd_node bgp_ipv6_unicast_node = {
	.name = "bgp ipv6 unicast",
	.node = BGP_IPV6_NODE,
	.parent_node = BGP_NODE,
	.prompt = "%s(config-router-af)# ",
	.no_xpath = true,
};

static struct cmd_node bgp_ipv6_multicast_node = {
	.name = "bgp ipv6 multicast",
	.node = BGP_IPV6M_NODE,
	.parent_node = BGP_NODE,
	.prompt = "%s(config-router-af)# ",
	.no_xpath = true,
};

static struct cmd_node bgp_ipv6_labeled_unicast_node = {
	.name = "bgp ipv6 labeled unicast",
	.node = BGP_IPV6L_NODE,
	.parent_node = BGP_NODE,
	.prompt = "%s(config-router-af)# ",
	.no_xpath = true,
};

static struct cmd_node bgp_vpnv4_node = {
	.name = "bgp vpnv4",
	.node = BGP_VPNV4_NODE,
	.parent_node = BGP_NODE,
	.prompt = "%s(config-router-af)# ",
	.no_xpath = true,
};

static struct cmd_node bgp_vpnv6_node = {
	.name = "bgp vpnv6",
	.node = BGP_VPNV6_NODE,
	.parent_node = BGP_NODE,
	.prompt = "%s(config-router-af-vpnv6)# ",
	.no_xpath = true,
};

static struct cmd_node bgp_evpn_node = {
	.name = "bgp evpn",
	.node = BGP_EVPN_NODE,
	.parent_node = BGP_NODE,
	.prompt = "%s(config-router-evpn)# ",
	.no_xpath = true,
};

static struct cmd_node bgp_evpn_vni_node = {
	.name = "bgp evpn vni",
	.node = BGP_EVPN_VNI_NODE,
	.parent_node = BGP_EVPN_NODE,
	.prompt = "%s(config-router-af-vni)# ",
};

static struct cmd_node bgp_flowspecv4_node = {
	.name = "bgp ipv4 flowspec",
	.node = BGP_FLOWSPECV4_NODE,
	.parent_node = BGP_NODE,
	.prompt = "%s(config-router-af)# ",
	.no_xpath = true,
};

static struct cmd_node bgp_flowspecv6_node = {
	.name = "bgp ipv6 flowspec",
	.node = BGP_FLOWSPECV6_NODE,
	.parent_node = BGP_NODE,
	.prompt = "%s(config-router-af-vpnv6)# ",
	.no_xpath = true,
};

static struct cmd_node bgp_ipv4_unreachability_node = {
	.name = "bgp ipv4 unreachability",
	.node = BGP_IPV4U_NODE,
	.parent_node = BGP_NODE,
	.prompt = "%s(config-router-af)# ",
	.no_xpath = true,
};

static struct cmd_node bgp_ipv6_unreachability_node = {
	.name = "bgp ipv6 unreachability",
	.node = BGP_IPV6U_NODE,
	.parent_node = BGP_NODE,
	.prompt = "%s(config-router-af)# ",
	.no_xpath = true,
};

static struct cmd_node bgp_srv6_node = {
	.name = "bgp srv6",
	.node = BGP_SRV6_NODE,
	.parent_node = BGP_NODE,
	.prompt = "%s(config-router-srv6)# ",
	/* SRv6 mode does not push xpath; keep BGP container on exit. */
	.no_xpath = true,
};

static struct cmd_node bgp_ls_node = {
	.name = "bgp link-state",
	.node = BGP_LS_NODE,
	.parent_node = BGP_NODE,
	.prompt = "%s(config-router-af)# ",
	.no_xpath = true,
};

static void community_list_vty(void);

static void bgp_ac_peergroup(vector comps, struct cmd_token *token)
{
	struct bgp *bgp;
	struct peer_group *group;
	struct listnode *lnbgp, *lnpeer;

	for (ALL_LIST_ELEMENTS_RO(bm->bgp, lnbgp, bgp)) {
		for (ALL_LIST_ELEMENTS_RO(bgp->group, lnpeer, group))
			vector_set(comps, XSTRDUP(MTYPE_COMPLETION, group->name));
	}
}

static void bgp_ac_peer(vector comps, struct cmd_token *token)
{
	struct bgp *bgp;
	struct peer *peer;
	struct listnode *lnbgp, *lnpeer;

	for (ALL_LIST_ELEMENTS_RO(bm->bgp, lnbgp, bgp)) {
		for (ALL_LIST_ELEMENTS_RO(bgp->peer, lnpeer, peer)) {
			/* only provide suggestions on the appropriate input
			 * token type,
			 * they'll otherwise show up multiple times
			 */
			enum cmd_token_type match_type;
			char *name = peer->host;

			if (peer->conf_if) {
				match_type = VARIABLE_TKN;
				name = peer->conf_if;
			} else if (strchr(peer->host, ':'))
				match_type = IPV6_TKN;
			else
				match_type = IPV4_TKN;

			if (token->type != match_type)
				continue;

			vector_set(comps, XSTRDUP(MTYPE_COMPLETION, name));
		}
	}
}

static void bgp_ac_neighbor(vector comps, struct cmd_token *token)
{
	bgp_ac_peer(comps, token);

	if (token->type == VARIABLE_TKN)
		bgp_ac_peergroup(comps, token);
}

static const struct cmd_variable_handler bgp_var_neighbor[] = {
	{.varname = "neighbor", .completions = bgp_ac_neighbor},
	{.varname = "neighbors", .completions = bgp_ac_neighbor},
	{.varname = "peer", .completions = bgp_ac_neighbor},
	{.completions = NULL}};

static const struct cmd_variable_handler bgp_var_peergroup[] = {
	{.tokenname = "PGNAME", .completions = bgp_ac_peergroup},
	{.completions = NULL} };

DEFINE_HOOK(bgp_config_end, (struct bgp *bgp), (bgp));

static struct event *t_bgp_cfg;

bool bgp_config_inprocess(void)
{
	return event_is_scheduled(t_bgp_cfg);
}

/* Max wait time for config to load before post-config processing */
#define BGP_PRE_CONFIG_MAX_WAIT_SECONDS 600

static void bgp_config_finish(struct event *t)
{
	struct listnode *node;
	struct bgp *bgp;

	for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, bgp))
		hook_call(bgp_config_end, bgp);
}

static void bgp_config_end_timeout(struct event *t)
{
	flog_err(EC_BGP_CONFIG_TIMEOUT, "BGP configuration end timer expired after %d seconds.",
		 BGP_PRE_CONFIG_MAX_WAIT_SECONDS);
	bgp_config_finish(t);
}

static void bgp_config_start(struct vty *vty)
{
	event_cancel(&t_bgp_cfg);
	event_add_timer(bm->master, bgp_config_end_timeout, NULL,
			BGP_PRE_CONFIG_MAX_WAIT_SECONDS, &t_bgp_cfg);
}

/* When we receive a hook the configuration is read,
 * we start a timer to make sure we postpone sending
 * EoR before route-maps are processed.
 * This is especially valid if using `bgp route-map delay-timer`.
 */
static void bgp_config_end(struct vty *vty)
{
#define BGP_POST_CONFIG_DELAY_SECONDS 1
	uint32_t bgp_post_config_delay =
		event_is_scheduled(bm->t_rmap_update)
			? event_timer_remain_second(bm->t_rmap_update)
			: BGP_POST_CONFIG_DELAY_SECONDS;

	/* If BGP config processing thread isn't running, then
	 * we can return and rely it's properly handled.
	 */
	if (!bgp_config_inprocess())
		return;

	SET_FLAG(bm->flags, BM_FLAG_CONFIG_LOADED);

	if (bgp_in_graceful_restart())
		bgp_gr_start_peers();

	event_cancel(&t_bgp_cfg);

	/* Start a new timer to make sure we don't send EoR
	 * before route-maps are processed.
	 */
	event_add_timer(bm->master, bgp_config_finish, NULL,
			bgp_post_config_delay, &t_bgp_cfg);
}

static int config_write_interface_one(struct vty *vty, struct vrf *vrf)
{
	int write = 0;
	struct interface *ifp;
	struct bgp_interface *iifp;

	FOR_ALL_INTERFACES (vrf, ifp) {
		iifp = ifp->info;
		if (!iifp)
			continue;

		if_vty_config_start(vty, ifp);

		if (CHECK_FLAG(iifp->flags,
			       BGP_INTERFACE_MPLS_BGP_FORWARDING)) {
			vty_out(vty, " mpls bgp forwarding\n");
			write++;
		}
		if (CHECK_FLAG(iifp->flags,
			       BGP_INTERFACE_MPLS_L3VPN_SWITCHING)) {
			vty_out(vty,
				" mpls bgp l3vpn-multi-domain-switching\n");
			write++;
		}

		if_vty_config_end(vty);
	}

	return write;
}

/* Configuration write function for bgpd. */
static int config_write_interface(struct vty *vty)
{
	int write = 0;
	struct vrf *vrf = NULL;

	/* Display all VRF aware OSPF interface configuration */
	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		write += config_write_interface_one(vty, vrf);
	}

	return write;
}


/* Initialization of BGP interface. */
static void bgp_vty_if_init(void)
{
	/* Install interface node. */
	if_cmd_init(config_write_interface);

	/* mpls bgp forwarding / l3vpn-multi-domain-switching — YANG: bgp_cli_init() */
}

/* Forward declaration for show_bgp_neighbor_upa_cmd defined after bgp_vty_init */
static const struct cmd_element show_bgp_neighbor_upa_cmd;

void bgp_vty_init(void)
{
	cmd_variable_handler_register(bgp_var_neighbor);
	cmd_variable_handler_register(bgp_var_peergroup);

	cmd_init_config_callbacks(bgp_config_start, bgp_config_end);

	/* Install bgp top node. */
	install_node(&bgp_node);
	install_node(&bgp_ipv4_unicast_node);
	install_node(&bgp_ipv4_multicast_node);
	install_node(&bgp_ipv4_labeled_unicast_node);
	install_node(&bgp_ipv6_unicast_node);
	install_node(&bgp_ipv6_multicast_node);
	install_node(&bgp_ipv6_labeled_unicast_node);
	install_node(&bgp_vpnv4_node);
	install_node(&bgp_vpnv6_node);
	install_node(&bgp_evpn_node);
	install_node(&bgp_evpn_vni_node);
	install_node(&bgp_flowspecv4_node);
	install_node(&bgp_flowspecv6_node);
	install_node(&bgp_ipv4_unreachability_node);
	install_node(&bgp_ipv6_unreachability_node);
	install_node(&bgp_srv6_node);
	install_node(&bgp_ls_node);

	/* Install default VTY commands to new nodes.  */
	install_default(BGP_NODE);
	install_default(BGP_IPV4_NODE);
	install_default(BGP_IPV4M_NODE);
	install_default(BGP_IPV4L_NODE);
	install_default(BGP_IPV6_NODE);
	install_default(BGP_IPV6M_NODE);
	install_default(BGP_IPV6L_NODE);
	install_default(BGP_VPNV4_NODE);
	install_default(BGP_VPNV6_NODE);
	install_default(BGP_FLOWSPECV4_NODE);
	install_default(BGP_FLOWSPECV6_NODE);
	install_default(BGP_IPV4U_NODE);
	install_default(BGP_IPV6U_NODE);
	install_default(BGP_EVPN_NODE);
	install_default(BGP_EVPN_VNI_NODE);
	install_default(BGP_SRV6_NODE);
	install_default(BGP_LS_NODE);

	/* global bgp inq-limit / outq-limit — YANG: bgp_cli_init() */

	/* "bgp local-mac" hidden commands. */
	install_element(CONFIG_NODE, &bgp_local_mac_cmd);
	install_element(CONFIG_NODE, &no_bgp_local_mac_cmd);

	/* "bgp suppress-fib-pending" global — YANG: bgp_cli_init() */

	/* bgp route-map delay-timer — YANG: bgp_cli_init() */

	/* bgp allow-martian-nexthop — YANG: bgp_cli_init() */

	/* bgp fast-convergence — YANG: bgp_cli_init() */

	/* global bgp ipv6-auto-ra — YANG: bgp_cli_init() */

	/* bgp ipv6-auto-ra (BGP_NODE) — YANG: bgp_cli_init() */

	/* global bgp update-delay — YANG: bgp_cli_init() */

	/* global bgp advertisement-delay — YANG: bgp_cli_init() */

	/* global bgp graceful-shutdown / graceful-restart — YANG: bgp_cli_init() */

	/* "router bgp" / globals converted to YANG — see bgp_cli_init(). */

	/* bgp session-dscp — YANG: bgp_cli_init() */

	/* "bgp router-id" — YANG: bgp_cli_init() */

	/* "bgp suppress-fib-pending" — YANG: bgp_cli_init() */

	/* "bgp cluster-id" — YANG: bgp_cli_init() */

	/* "bgp no-rib" — YANG: bgp_cli_init() */

	/* bgp send-extra-data zebra — YANG: bgp_cli_init() */

	/* "bgp confederation" — YANG: bgp_cli_init() */

	/* "bgp confederation peers" — YANG: bgp_cli_init() */

	/* bgp max-med — YANG: bgp_cli_init() */

	/* "neighbor role" commands. */

	/* "neighbor oad" commands. */

	/* "neighbor aigp" commands. */

	/* "neighbor graceful-shutdown" command */

	/* bgp disable-ebgp-connected-nh-check — YANG: bgp_cli_init() */

	/* update-delay / advertisement-delay — YANG: bgp_cli_init() */

	/* write/read-quanta, coalesce-time, use-underlays — YANG: bgp_cli_init() */

	/* "nexthop prefer-global" — YANG: bgp_cli_init() */

	/* "maximum-paths" commands. */


	/* "timers bgp" / minimum-holdtime — YANG: bgp_cli_init() */

	/* route-map delay-timer — BGP_NODE + CONFIG_NODE YANG: bgp_cli_init() */

	/* "bgp client-to-client reflection" — YANG: bgp_cli_init() */

	/* "bgp always-compare-med" — YANG: bgp_cli_init() */

	/* bgp ebgp-requires-policy — YANG: bgp_cli_init() */

	/* bgp enforce-first-as — YANG: bgp_cli_init() */

	/* bgp labeled-unicast explicit-null — YANG: bgp_cli_init() */

	/* bgp suppress-duplicates — YANG: bgp_cli_init() */

	/* bgp reject-as-sets — YANG: bgp_cli_init() */

	/* "bgp deterministic-med" — YANG: bgp_cli_init() */

	/* "bgp default-originate set-only-unconditional" — YANG: bgp_cli_init() */

	/* GR mode enable/disable — BGP_NODE + CONFIG_NODE YANG: bgp_cli_init() */

	/* "neighbor a:b:c:d graceful-restart" command */

	/* "neighbor a:b:c:d graceful-restart-disable" command */

	/* "neighbor a:b:c:d graceful-restart-helper" command */

	/* GR timer/flag knobs — BGP_NODE + CONFIG_NODE YANG: bgp_cli_init() */

	/* "bgp graceful-shutdown" — BGP_NODE + CONFIG_NODE YANG: bgp_cli_init() */

	/* "bgp hard-administrative-reset" — YANG: bgp_cli_init() */

	/* "bgp long-lived-graceful-restart" — YANG: bgp_cli_init() */

	/* "bgp fast-external-failover" — YANG: bgp_cli_init() */

	/* "bgp bestpath aigp" — YANG: bgp_cli_init() */

	/* "bgp bestpath compare-routerid" — YANG: bgp_cli_init() */

	/* "bgp bestpath as-path ignore" — YANG: bgp_cli_init() */

	/* "bgp bestpath use-imported-attributes" — YANG: bgp_cli_init() */

	/* "bgp bestpath prefer-mpls-over-srv6" — YANG: bgp_cli_init() */

	/* "bgp bestpath as-path confed" — YANG: bgp_cli_init() */

	/* "bgp bestpath as-path multipath-relax" — YANG: bgp_cli_init() */

	/* "bgp bestpath peer-type multipath-relax" — YANG: bgp_cli_init() */

	/* "bgp log-neighbor-changes" — YANG: bgp_cli_init() */

	/* "bgp bestpath med" — YANG: bgp_cli_init() */

	/* "bgp bestpath bandwidth" — YANG: bgp_cli_init() */

	/* "bgp default <afi>-<safi>" — YANG: bgp_cli_init() */

	/* "bgp network import-check" — YANG: bgp_cli_init() */

	/* "bgp default local-preference" — YANG: bgp_cli_init() */

	/* bgp default show-hostname — YANG: bgp_cli_init() */

	/* bgp default show-nexthop-hostname — YANG: bgp_cli_init() */

	/* bgp default software-version / link-local / dynamic-capability —
	 * YANG: bgp_cli_init()
	 */

	/* "bgp default subgroup-pkt-queue-max" — YANG: bgp_cli_init() */

	/* bgp route-reflector allow-outbound-policy — YANG: bgp_cli_init() */

	/* "bgp listen limit" / "bgp listen range" — YANG: bgp_cli_init() */

	/* "bgp default shutdown" / "bgp shutdown" — YANG: bgp_cli_init() */

	/* "neighbor remote-as" / "no neighbor" / interface — YANG: bgp_cli_init() */

	/* "neighbor peer-group" — YANG: bgp_cli_init() */

	/* "neighbor local-as" commands. */

	/* "neighbor solo" — YANG: bgp_cli_init() */

	/* "neighbor password" — YANG: bgp_cli_init() */

	/* "neighbor activate" — YANG: bgp_cli_init() */

	/* "no neighbor activate" — YANG: bgp_cli_init() */

	/* "neighbor peer-group" set on AF nodes — YANG: bgp_cli_init() */

	/* "neighbor softreconfiguration inbound" commands.*/

	/* "neighbor attribute-unchanged" commands.  */


	/* "nexthop-local unchanged" commands */

	/* "neighbor next-hop-self" commands. */

	/* "neighbor next-hop-self force" commands. */

	/* "neighbor as-override" commands. */

	/* "neighbor remove-private-AS" commands. */

	/* "neighbor send-community" commands.*/

	/* "neighbor route-reflector" commands.*/

	/* "neighbor route-server" commands.*/

	/* "neighbor disable-addpath-rx" commands. */

	/* "neighbor addpath-tx-all-paths" commands.*/

	/* "neighbor addpath-tx-best-selected" commands.*/

	/* "neighbor addpath-tx-bestpath-per-AS" commands.*/

	/* "neighbor addpath-rx-paths-limit" commands.*/

	/* "neighbor sender-as-path-loop-detection" — YANG: bgp_cli_init() */

	/* "neighbor path-attribute discard" commands. */

	/* "neighbor path-attribute treat-as-withdraw" commands. */

	/* "neighbor passive" — YANG: bgp_cli_init() */

	/* "neighbor upa" commands. */

	install_element(VIEW_NODE, &show_bgp_neighbor_upa_cmd);

	/* "neighbor shutdown" — YANG: bgp_cli_init()
	 * (including shutdown rtt)
	 */

	/* "neighbor capability extended-nexthop" commands.*/

	/* "neighbor capability software-version" commands.*/

	/* "neighbor capability link-local" commands.*/

	/* neighbor rpki ... commands. */

	/* "neighbor capability orf prefix-list" commands.*/

	/* "neighbor capability dynamic" commands.*/

	/* "neighbor dont-capability-negotiate" commands. */

	/* "neighbor capability fqdn" command. */

	/* "neighbor ebgp-multihop" commands. */

	/* "neighbor disable-connected-check" commands.  */

	/* neighbor disable-link-bw-encoding-ieee / extended-link-bandwidth /
	 * send-nexthop-characteristics / extended-optional-parameters —
	 * YANG: bgp_cli_init()
	 */

	/* "neighbor enforce-first-as" commands. */

	/* "neighbor description" — YANG: bgp_cli_init() */

	/* "neighbor update-source" commands. "*/

	/* "neighbor default-originate" commands. */

	/* "neighbor port" commands. */

	/* "neighbor weight" commands. */


	/* neighbor encapsulation-srv6|mpls — YANG: bgp_cli_init() */

	/* "neighbor override-capability" commands. */

	/* "neighbor strict-capability-match" commands. */

	/* "neighbor timers" commands. */

	/* "neighbor timers connect" commands. */

	/* "neighbor timers delayopen" commands. */

	/* "neighbor advertisement-interval" commands. */

	/* "neighbor interface" — YANG: bgp_cli_init() */

	/* "neighbor distribute" commands. */

	/* "neighbor prefix-list" commands. */

	/* "neighbor filter-list" commands. */

	/* "neighbor route-map" — YANG: bgp_cli_init() */

	/* "neighbor unsuppress-map" commands. */

	/* "neighbor advertise-map" commands. */

	/* bgp default-originate timer */

	/* neighbor maximum-prefix / allowas-in on UPA — YANG: bgp_cli_init() */

	/* neighbor accept-own */

	/* "neighbor soo" */

	/* "neighbor dampening" commands. */
	/* neighbor dampening: YANG in bgp_cli.c */
	install_element(VIEW_NODE, &show_ip_bgp_neighbor_damp_param_cmd);

	/* address-family enter — YANG: bgp_cli_init() */

	/* "exit-address-family" command. */
	install_element(BGP_IPV4_NODE, &exit_address_family_cmd);
	install_element(BGP_IPV4M_NODE, &exit_address_family_cmd);
	install_element(BGP_IPV4L_NODE, &exit_address_family_cmd);
	install_element(BGP_IPV6_NODE, &exit_address_family_cmd);
	install_element(BGP_IPV6M_NODE, &exit_address_family_cmd);
	install_element(BGP_IPV6L_NODE, &exit_address_family_cmd);
	install_element(BGP_VPNV4_NODE, &exit_address_family_cmd);
	install_element(BGP_VPNV6_NODE, &exit_address_family_cmd);
	install_element(BGP_FLOWSPECV4_NODE, &exit_address_family_cmd);
	install_element(BGP_FLOWSPECV6_NODE, &exit_address_family_cmd);
	install_element(BGP_IPV4U_NODE, &exit_address_family_cmd);
	install_element(BGP_IPV6U_NODE, &exit_address_family_cmd);
	install_element(BGP_EVPN_NODE, &exit_address_family_cmd);
	install_element(BGP_LS_NODE, &exit_address_family_cmd);

	/* BGP retain all route-target */
	/* bgp retain route-target — YANG: bgp_cli_init() */

#ifdef DEV_BUILD
	/* "bgp test" commands */
	install_element(ENABLE_NODE, &bgp_test_metaq_plug_cmd);
	install_element(ENABLE_NODE, &bgp_test_updates_plug_cmd);
#endif

	/* "clear ip bgp commands" */
	install_element(ENABLE_NODE, &clear_ip_bgp_all_cmd);

	/* clear ip bgp prefix  */
	install_element(ENABLE_NODE, &clear_ip_bgp_prefix_cmd);
	install_element(ENABLE_NODE, &clear_bgp_ipv6_safi_prefix_cmd);
	install_element(ENABLE_NODE, &clear_bgp_instance_ipv6_safi_prefix_cmd);

	/* "show [ip] bgp summary" commands. */
	install_element(VIEW_NODE, &show_bgp_instance_all_ipv6_updgrps_cmd);
	install_element(VIEW_NODE, &show_bgp_l2vpn_evpn_updgrps_cmd);
	install_element(VIEW_NODE, &show_bgp_instance_updgrps_stats_cmd);
	install_element(VIEW_NODE, &show_bgp_updgrps_stats_cmd);
	install_element(VIEW_NODE, &show_ip_bgp_instance_updgrps_adj_s_cmd);
	install_element(VIEW_NODE, &show_ip_bgp_summary_cmd);
	install_element(VIEW_NODE, &show_ip_bgp_updgrps_cmd);

	/* "show [ip] bgp neighbors" commands. */
	install_element(VIEW_NODE, &show_ip_bgp_neighbors_cmd);
	install_element(VIEW_NODE, &show_bgp_neighbor_orf_prefix_list_cmd);

	/* "show [ip] bgp peer-group" commands. */
	install_element(VIEW_NODE, &show_ip_bgp_peer_groups_cmd);

	/* "show [ip] bgp paths" commands. */
	install_element(VIEW_NODE, &show_ip_bgp_paths_cmd);

	/* "show [ip] bgp community" commands. */
	install_element(VIEW_NODE, &show_ip_bgp_community_info_cmd);

	/* "show ip bgp large-community" commands. */
	install_element(VIEW_NODE, &show_ip_bgp_lcommunity_info_cmd);
	/* "show [ip] bgp attribute-info" commands. */
	install_element(VIEW_NODE, &show_ip_bgp_attr_info_cmd);
	/* "show [ip] bgp route-leak" command */
	install_element(VIEW_NODE, &show_ip_bgp_route_leak_cmd);

	/* "show bgp aggregate-address" command */
	install_element(VIEW_NODE, &show_bgp_aggregate_cmd);

	/* "redistribute" commands — YANG: bgp_cli_init() */

	/* redistribute show commands */
	install_element(VIEW_NODE, &show_bgp_redistribute_cmd);

	/* import|export vpn — YANG: bgp_cli_init() */
	/* import vrf — YANG: bgp_cli_init() */

	/* ttl_security commands */

	/* "bgp tcp-keepalive" — YANG: bgp_cli_init() */

	/* "show [ip] bgp memory" commands. */
	install_element(VIEW_NODE, &show_bgp_memory_cmd);

	/* "show bgp martian next-hop" */
	install_element(VIEW_NODE, &show_bgp_martian_nexthop_db_cmd);

	install_element(VIEW_NODE, &show_bgp_mac_hash_cmd);

	/* "show [ip] bgp views" commands. */
	install_element(VIEW_NODE, &show_bgp_views_cmd);

	/* "show [ip] bgp vrfs" commands. */
	install_element(VIEW_NODE, &show_bgp_vrfs_cmd);

	/* Some overall BGP information */
	install_element(VIEW_NODE, &show_bgp_router_cmd);

	/* "show bgp vrfs bestpath" command. */
	install_element(VIEW_NODE, &show_bgp_vrf_bestpath_cmd);

	/* Community-list. */
	community_list_vty();

	community_alias_vty();

	/* vpn-policy commands */
	/* rd / label / nexthop / rt vpn — YANG: bgp_cli_init() */
	/* route-map vpn / import vrf route-map — YANG: bgp_cli_init() */

	/* rt redirect import — YANG: bgp_cli_init() */

	/* no rd / label / rt vpn — YANG: bgp_cli_init() */
	/* no route-map vpn / import vrf route-map — YANG: bgp_cli_init() */

	/* tcp-mss command */


	/* srv6 commands */
	/* segment-routing srv6 — YANG: bgp_cli_init() */
	install_element(VIEW_NODE, &show_bgp_srv6_cmd);
	/* sid vpn export (AF) — YANG: bgp_cli_init() */
	/* sid vpn per-vrf export — YANG: bgp_cli_init() */
	/* sid export — YANG: bgp_cli_init() */
	/* neighbor encapsulation-srv6 — YANG: bgp_cli_init() */

	/* BGP-LS commands */
	/* distribute bgp-fabric-link-state — YANG: bgp_cli_init() */
	/* neighbor local/remote-link-id — YANG: bgp_cli_init() */

	/* UPA global origination commands - for all prefixes, not just aggregates */
	/* AF-level UPA — YANG: bgp_cli_init() */

	bgp_vty_if_init();

	bgp_unreach_vty_init();

	/* YANG-backed CLI for converted BGP commands */
	bgp_cli_init();
}

/* Show UPA information for a specific neighbor */
DEFPY(show_bgp_neighbor_upa, show_bgp_neighbor_upa_cmd,
      "show bgp [<ipv4|ipv6>$afi_str [unicast]] neighbors <A.B.C.D|X:X::X:X|WORD>$neighbor upa [json$uj]",
      SHOW_STR BGP_STR IP_STR IPV6_STR
      "Address Family modifier\n"
      "Detailed information on TCP and BGP neighbor connections\n"
      "Neighbor to display information about\n"
      "Neighbor to display information about\n"
      "Neighbor on BGP configured interface\n"
      "UPA (Unreachable Prefix Announcement) information\n"
      JSON_STR)
{
	struct bgp *bgp;
	struct peer *peer;
	bool use_json = !!uj;
	json_object *json = NULL;
	afi_t afi = AFI_IP;
	safi_t safi = SAFI_UNICAST;

	bgp = bgp_get_default();
	if (!bgp) {
		vty_out(vty, "No BGP process is configured\n");
		return CMD_WARNING;
	}

	if (afi_str && strmatch(afi_str, "ipv6"))
		afi = AFI_IP6;

	peer = peer_lookup_in_view(vty, bgp, neighbor, use_json);
	if (!peer)
		return CMD_WARNING;

	if (use_json) {
		json = json_object_new_object();
		json_object_string_add(json, "peer", peer->host);
		json_object_boolean_add(json, "upaSendEnabled",
					CHECK_FLAG(peer->af_flags[afi][safi], PEER_FLAG_UPA));
		vty_json(vty, json);
	} else {
		vty_out(vty, "BGP neighbor %s UPA information:\n\n", peer->host);
		vty_out(vty, "  UPA send enabled: %s\n",
			CHECK_FLAG(peer->af_flags[afi][safi], PEER_FLAG_UPA) ? "yes" : "no");
	}

	return CMD_SUCCESS;
}

#include "memory.h"
#include "bgp_regex.h"
#include "bgp_clist.h"
#include "bgp_ecommunity.h"

/* VTY functions.  */

/* Direction value to string conversion.  */
static const char *community_direct_str(int direct)
{
	switch (direct) {
	case COMMUNITY_DENY:
		return "deny";
	case COMMUNITY_PERMIT:
		return "permit";
	default:
		return "unknown";
	}
}

/* "community-list" keyword help string.  */

/* Return configuration string of community-list entry.  */
static const char *community_list_config_str(struct community_entry *entry)
{
	const char *str;

	if (entry->style == COMMUNITY_LIST_STANDARD)
		str = community_str(entry->u.com, false);
	else if (entry->style == LARGE_COMMUNITY_LIST_STANDARD)
		str = lcommunity_str(entry->u.lcom, false);
	else
		str = entry->config;

	return str;
}

static void community_list_show(struct vty *vty, struct community_list *list)
{
	struct community_entry *entry;

	for (entry = list->head; entry; entry = entry->next) {
		if (entry == list->head) {
			if (all_digit(list->name))
				vty_out(vty, "Community %s list %s\n",
					entry->style == COMMUNITY_LIST_STANDARD
						? "standard"
						: "(expanded) access",
					list->name);
			else
				vty_out(vty, "Named Community %s list %s\n",
					entry->style == COMMUNITY_LIST_STANDARD
						? "standard"
						: "expanded",
					list->name);
		}
		vty_out(vty, "    %s %s\n", community_direct_str(entry->direct),
			community_list_config_str(entry));
	}
}

DEFUN (show_community_list,
       show_bgp_community_list_cmd,
       "show bgp community-list",
       SHOW_STR
       BGP_STR
       "List community-list\n")
{
	struct community_list *list;
	struct community_list_master *cm;

	cm = community_list_master_lookup(bgp_clist, COMMUNITY_LIST_MASTER);
	if (!cm)
		return CMD_SUCCESS;

	for (list = cm->num.head; list; list = list->next)
		community_list_show(vty, list);

	for (list = cm->str.head; list; list = list->next)
		community_list_show(vty, list);

	return CMD_SUCCESS;
}

DEFUN (show_community_list_arg,
       show_bgp_community_list_arg_cmd,
       "show bgp community-list <(1-500)|COMMUNITY_LIST_NAME> detail",
       SHOW_STR
       BGP_STR
       "List community-list\n"
       "Community-list number\n"
       "Community-list name\n"
       "Detailed information on community-list\n")
{
	int idx_comm_list = 3;
	struct community_list *list;

	list = community_list_lookup(bgp_clist, argv[idx_comm_list]->arg, 0,
				     COMMUNITY_LIST_MASTER);
	if (!list) {
		vty_out(vty, "%% Can't find community-list\n");
		return CMD_WARNING;
	}

	community_list_show(vty, list);

	return CMD_SUCCESS;
}

/* "large-community-list" keyword help string.  */

static void lcommunity_list_show(struct vty *vty, struct community_list *list)
{
	struct community_entry *entry;

	for (entry = list->head; entry; entry = entry->next) {
		if (entry == list->head) {
			if (all_digit(list->name))
				vty_out(vty, "Large community %s list %s\n",
					entry->style ==
						LARGE_COMMUNITY_LIST_STANDARD
						? "standard"
						: "(expanded) access",
					list->name);
			else
				vty_out(vty,
					"Named large community %s list %s\n",
					entry->style ==
						LARGE_COMMUNITY_LIST_STANDARD
						? "standard"
						: "expanded",
					list->name);
		}
		vty_out(vty, "    %s %s\n", community_direct_str(entry->direct),
			community_list_config_str(entry));
	}
}

DEFUN (show_lcommunity_list,
       show_bgp_lcommunity_list_cmd,
       "show bgp large-community-list",
       SHOW_STR
       BGP_STR
       "List large-community list\n")
{
	struct community_list *list;
	struct community_list_master *cm;

	cm = community_list_master_lookup(bgp_clist,
					  LARGE_COMMUNITY_LIST_MASTER);
	if (!cm)
		return CMD_SUCCESS;

	for (list = cm->num.head; list; list = list->next)
		lcommunity_list_show(vty, list);

	for (list = cm->str.head; list; list = list->next)
		lcommunity_list_show(vty, list);

	return CMD_SUCCESS;
}

DEFUN (show_lcommunity_list_arg,
       show_bgp_lcommunity_list_arg_cmd,
       "show bgp large-community-list <(1-500)|LCOMMUNITY_LIST_NAME> detail",
       SHOW_STR
       BGP_STR
       "List large-community list\n"
       "Large-community-list number\n"
       "Large-community-list name\n"
       "Detailed information on large-community-list\n")
{
	struct community_list *list;

	list = community_list_lookup(bgp_clist, argv[3]->arg, 0,
				     LARGE_COMMUNITY_LIST_MASTER);
	if (!list) {
		vty_out(vty, "%% Can't find large-community-list\n");
		return CMD_WARNING;
	}

	lcommunity_list_show(vty, list);

	return CMD_SUCCESS;
}

/* "extcommunity-list" keyword help string.  */

static void extcommunity_list_show(struct vty *vty, struct community_list *list)
{
	struct community_entry *entry;

	for (entry = list->head; entry; entry = entry->next) {
		if (entry == list->head) {
			if (all_digit(list->name))
				vty_out(vty, "Extended community %s list %s\n",
					entry->style == EXTCOMMUNITY_LIST_STANDARD
						? "standard"
						: "(expanded) access",
					list->name);
			else
				vty_out(vty,
					"Named extended community %s list %s\n",
					entry->style == EXTCOMMUNITY_LIST_STANDARD
						? "standard"
						: "expanded",
					list->name);
		}
		vty_out(vty, "    %s %s\n", community_direct_str(entry->direct),
			community_list_config_str(entry));
	}
}

DEFUN (show_extcommunity_list,
       show_bgp_extcommunity_list_cmd,
       "show bgp extcommunity-list",
       SHOW_STR
       BGP_STR
       "List extended-community list\n")
{
	struct community_list *list;
	struct community_list_master *cm;

	cm = community_list_master_lookup(bgp_clist, EXTCOMMUNITY_LIST_MASTER);
	if (!cm)
		return CMD_SUCCESS;

	for (list = cm->num.head; list; list = list->next)
		extcommunity_list_show(vty, list);

	for (list = cm->str.head; list; list = list->next)
		extcommunity_list_show(vty, list);

	return CMD_SUCCESS;
}

DEFUN (show_extcommunity_list_arg,
       show_bgp_extcommunity_list_arg_cmd,
       "show bgp extcommunity-list <(1-500)|EXTCOMMUNITY_LIST_NAME> detail",
       SHOW_STR
       BGP_STR
       "List extended-community list\n"
       "Extcommunity-list number\n"
       "Extcommunity-list name\n"
       "Detailed information on extcommunity-list\n")
{
	int idx_comm_list = 3;
	struct community_list *list;

	list = community_list_lookup(bgp_clist, argv[idx_comm_list]->arg, 0,
				     EXTCOMMUNITY_LIST_MASTER);
	if (!list) {
		vty_out(vty, "%% Can't find extcommunity-list\n");
		return CMD_WARNING;
	}

	extcommunity_list_show(vty, list);

	return CMD_SUCCESS;
}

/* Display community-list and extcommunity-list configuration.  */
struct clist_write_ctx {
	const struct lyd_node **nodes;
	size_t count;
	size_t cap;
};

static int clist_collect_cb(const struct lyd_node *dnode, void *arg)
{
	struct clist_write_ctx *ctx = arg;

	if (ctx->count == ctx->cap) {
		ctx->cap = ctx->cap ? ctx->cap * 2 : 16;
		ctx->nodes = XREALLOC(MTYPE_TMP, ctx->nodes,
				      ctx->cap * sizeof(*ctx->nodes));
	}
	ctx->nodes[ctx->count++] = dnode;
	return YANG_ITER_CONTINUE;
}

static bool clist_is_numbered_name(const char *name, unsigned long *num_out)
{
	unsigned long val;
	char *end = NULL;

	if (!name || !all_digit(name))
		return false;
	val = strtoul(name, &end, 10);
	if (!end || *end != '\0' || val < 1 || val > 500)
		return false;
	if (num_out)
		*num_out = val;
	return true;
}

static int clist_name_cmp(const void *a, const void *b)
{
	const struct lyd_node *na = *(const struct lyd_node *const *)a;
	const struct lyd_node *nb = *(const struct lyd_node *const *)b;
	const char *sa = yang_dnode_get_string(na, "name");
	const char *sb = yang_dnode_get_string(nb, "name");
	unsigned long va = 0, vb = 0;
	bool numa = clist_is_numbered_name(sa, &va);
	bool numb = clist_is_numbered_name(sb, &vb);

	if (numa && numb) {
		if (va < vb)
			return -1;
		if (va > vb)
			return 1;
		return strcmp(sa, sb);
	}
	if (numa != numb)
		return numa ? -1 : 1;
	return strcmp(sa, sb);
}

static int clist_entry_seq_cmp(const void *a, const void *b)
{
	const struct lyd_node *na = *(const struct lyd_node *const *)a;
	const struct lyd_node *nb = *(const struct lyd_node *const *)b;
	uint32_t sa = yang_dnode_get_uint32(na, "sequence");
	uint32_t sb = yang_dnode_get_uint32(nb, "sequence");

	if (sa < sb)
		return -1;
	if (sa > sb)
		return 1;
	return 0;
}

static int community_list_config_write_xpath(struct vty *vty, const char *xpath)
{
	struct clist_write_ctx lists = {};
	int write = 0;

	yang_dnode_iterate(clist_collect_cb, &lists, running_config->dnode, "%s", xpath);
	if (lists.count > 1)
		qsort(lists.nodes, lists.count, sizeof(*lists.nodes), clist_name_cmp);

	for (size_t i = 0; i < lists.count; i++) {
		struct clist_write_ctx entries = {};

		yang_dnode_iterate(clist_collect_cb, &entries, lists.nodes[i], "entry");
		if (entries.count > 1)
			qsort(entries.nodes, entries.count, sizeof(*entries.nodes),
			      clist_entry_seq_cmp);
		for (size_t j = 0; j < entries.count; j++) {
			nb_cli_show_dnode_cmds(vty, entries.nodes[j], false);
			write++;
		}
		XFREE(MTYPE_TMP, entries.nodes);
	}
	XFREE(MTYPE_TMP, lists.nodes);
	return write;
}

static int community_list_config_write(struct vty *vty)
{
	int write = 0;

	write += community_list_config_write_xpath(
		vty, "/frr-filter:lib/frr-bgp-filter:community-list");
	write += community_list_config_write_xpath(
		vty, "/frr-filter:lib/frr-bgp-filter:extcommunity-list");
	write += community_list_config_write_xpath(
		vty, "/frr-filter:lib/frr-bgp-filter:large-community-list");
	return write;
}

static struct cmd_node community_list_node = {
	.name = "community list",
	.node = COMMUNITY_LIST_NODE,
	.prompt = "",
	.config_write = community_list_config_write,
};

static void community_list_vty(void)
{
	install_node(&community_list_node);

	/* Community/ext/large-community-list config — YANG: bgp_filter_cli_init() */
	install_element(VIEW_NODE, &show_bgp_community_list_cmd);
	install_element(VIEW_NODE, &show_bgp_community_list_arg_cmd);

	install_element(VIEW_NODE, &show_bgp_extcommunity_list_cmd);
	install_element(VIEW_NODE, &show_bgp_extcommunity_list_arg_cmd);

	install_element(VIEW_NODE, &show_bgp_lcommunity_list_cmd);
	install_element(VIEW_NODE, &show_bgp_lcommunity_list_arg_cmd);

	bgp_community_list_command_completion_setup();
}

static struct cmd_node community_alias_node = {
	.name = "community alias",
	.node = COMMUNITY_ALIAS_NODE,
	.prompt = "",
	/* Dumped via /frr-bgp:bgp-daemon cli_show from bgp_config_write. */
	.config_write = NULL,
};

void community_alias_vty(void)
{
	install_node(&community_alias_node);

	/* Community alias — YANG: bgp_cli_init() */

	bgp_community_alias_command_completion_setup();
}
