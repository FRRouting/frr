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

#include "bgpd/bgpd.h"
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
#ifdef ENABLE_BGP_VNC
#include "bgpd/rfapi/bgp_rfapi_cfg.h"
#endif

FRR_CFG_DEFAULT_BOOL(BGP_IMPORT_CHECK,
	{
		.val_bool = false,
			.match_profile = "traditional",
			.match_version = "< 7.4",
	},
	{ .val_bool = true },
);
FRR_CFG_DEFAULT_BOOL(BGP_SHOW_HOSTNAME,
	{ .val_bool = true, .match_profile = "datacenter", },
	{ .val_bool = false },
);
FRR_CFG_DEFAULT_BOOL(BGP_SHOW_NEXTHOP_HOSTNAME,
	{ .val_bool = true, .match_profile = "datacenter", },
	{ .val_bool = false },
);
FRR_CFG_DEFAULT_BOOL(BGP_LOG_NEIGHBOR_CHANGES,
	{ .val_bool = true, .match_profile = "datacenter", },
	{ .val_bool = false },
);
FRR_CFG_DEFAULT_BOOL(BGP_DETERMINISTIC_MED,
	{ .val_bool = true, .match_profile = "datacenter", },
	{ .val_bool = false },
);
FRR_CFG_DEFAULT_ULONG(BGP_CONNECT_RETRY,
	{ .val_ulong = 10, .match_profile = "datacenter", },
	{ .val_ulong = 120 },
);
FRR_CFG_DEFAULT_ULONG(BGP_HOLDTIME,
	{ .val_ulong = 9, .match_profile = "datacenter", },
	{ .val_ulong = 180 },
);
FRR_CFG_DEFAULT_ULONG(BGP_KEEPALIVE,
	{ .val_ulong = 3, .match_profile = "datacenter", },
	{ .val_ulong = 60 },
);
FRR_CFG_DEFAULT_BOOL(BGP_EBGP_REQUIRES_POLICY,
	{ .val_bool = false, .match_profile = "datacenter", },
	{ .val_bool = false, .match_version = "< 7.4", },
	{ .val_bool = true },
);
FRR_CFG_DEFAULT_BOOL(BGP_SUPPRESS_DUPLICATES,
	{ .val_bool = false, .match_version = "< 7.6", },
	{ .val_bool = true },
);
FRR_CFG_DEFAULT_BOOL(BGP_GRACEFUL_NOTIFICATION,
	{ .val_bool = false, .match_version = "< 8.3", },
	{ .val_bool = true },
);
FRR_CFG_DEFAULT_BOOL(BGP_HARD_ADMIN_RESET,
	{ .val_bool = false, .match_version = "< 8.3", },
	{ .val_bool = true },
);
FRR_CFG_DEFAULT_BOOL(BGP_SOFT_VERSION_CAPABILITY,
	{ .val_bool = true, .match_profile = "datacenter", },
	{ .val_bool = false },
);
FRR_CFG_DEFAULT_BOOL(BGP_DYNAMIC_CAPABILITY,
	{ .val_bool = true, .match_profile = "datacenter", },
	{ .val_bool = false },
);
FRR_CFG_DEFAULT_BOOL(BGP_ENFORCE_FIRST_AS,
	{ .val_bool = false, .match_version = "< 9.1", },
	{ .val_bool = true },
);

DEFINE_HOOK(bgp_inst_config_write,
		(struct bgp *bgp, struct vty *vty),
		(bgp, vty));
DEFINE_HOOK(bgp_snmp_update_last_changed, (struct bgp *bgp), (bgp));
DEFINE_HOOK(bgp_snmp_init_stats, (struct bgp *bgp), (bgp));
DEFINE_HOOK(bgp_snmp_traps_config_write, (struct vty * vty), (vty));

static struct peer_group *listen_range_exists(struct bgp *bgp,
					      struct prefix *range, int exact);

/* Show BGP peer's information. */
enum show_type {
	show_all,
	show_peer,
	show_ipv4_all,
	show_ipv6_all,
	show_ipv4_peer,
	show_ipv6_peer
};

static struct peer_group *listen_range_exists(struct bgp *bgp,
					      struct prefix *range, int exact);

static void bgp_show_global_graceful_restart_mode_vty(struct vty *vty,
						      struct bgp *bgp);

static int bgp_show_neighbor_graceful_restart_afi_all(struct vty *vty, struct bgp *bgp,
						      enum show_type type, const char *ip_str,
						      afi_t afi, bool use_json);

static enum node_type bgp_node_type(afi_t afi, safi_t safi)
{
	switch (afi) {
	case AFI_IP:
		switch (safi) {
		case SAFI_UNICAST:
			return BGP_IPV4_NODE;
		case SAFI_MULTICAST:
			return BGP_IPV4M_NODE;
		case SAFI_LABELED_UNICAST:
			return BGP_IPV4L_NODE;
		case SAFI_MPLS_VPN:
			return BGP_VPNV4_NODE;
		case SAFI_FLOWSPEC:
			return BGP_FLOWSPECV4_NODE;
		case SAFI_UNSPEC:
		case SAFI_ENCAP:
		case SAFI_EVPN:
		case SAFI_MAX:
			/* not expected */
			return BGP_IPV4_NODE;
		}
		break;
	case AFI_IP6:
		switch (safi) {
		case SAFI_UNICAST:
			return BGP_IPV6_NODE;
		case SAFI_MULTICAST:
			return BGP_IPV6M_NODE;
		case SAFI_LABELED_UNICAST:
			return BGP_IPV6L_NODE;
		case SAFI_MPLS_VPN:
			return BGP_VPNV6_NODE;
		case SAFI_FLOWSPEC:
			return BGP_FLOWSPECV6_NODE;
		case SAFI_UNSPEC:
		case SAFI_ENCAP:
		case SAFI_EVPN:
		case SAFI_MAX:
			/* not expected and the return value seems wrong */
			return BGP_IPV4_NODE;
		}
		break;
	case AFI_L2VPN:
		return BGP_EVPN_NODE;
	case AFI_UNSPEC:
	case AFI_MAX:
		// We should never be here but to clarify the switch statement..
		return BGP_IPV4_NODE;
	}

	// Impossible to happen
	return BGP_IPV4_NODE;
}

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
	} else if (afi == AFI_L2VPN) {
		if (safi == SAFI_EVPN)
			return "L2VPN EVPN";
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
	} else if (afi == AFI_L2VPN) {
		if (safi == SAFI_EVPN)
			return "l2VpnEvpn";
	}

	return "Unknown";
}

/* unset srv6 locator */
static int bgp_srv6_locator_unset(struct bgp *bgp)
{
	struct listnode *node, *nnode;
	struct srv6_locator_chunk *chunk;
	struct bgp_srv6_function *func;
	struct bgp *bgp_vrf;

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
		if (bgp_vrf->inst_type != BGP_INSTANCE_TYPE_VRF)
			continue;

		/* refresh vpnv4 tovpn_sid */
		XFREE(MTYPE_BGP_SRV6_SID,
		      bgp_vrf->vpn_policy[AFI_IP].tovpn_sid);

		/* refresh vpnv6 tovpn_sid */
		XFREE(MTYPE_BGP_SRV6_SID,
		      bgp_vrf->vpn_policy[AFI_IP6].tovpn_sid);

		/* refresh per-vrf tovpn_sid */
		XFREE(MTYPE_BGP_SRV6_SID, bgp_vrf->tovpn_sid);
	}

	/* update vpn bgp processes */
	vpn_leak_postchange_all();

	/* refresh tovpn_sid_locator */
	for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, bgp_vrf)) {
		if (bgp_vrf->inst_type != BGP_INSTANCE_TYPE_VRF)
			continue;

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

	/* clear locator name */
	memset(bgp->srv6_locator_name, 0, sizeof(bgp->srv6_locator_name));

	/* clear SRv6 locator */
	if (bgp->srv6_locator) {
		srv6_locator_free(bgp->srv6_locator);
		bgp->srv6_locator = NULL;
	}

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
		afi = AFI_IP6;
		break;
	case BGP_EVPN_NODE:
		afi = AFI_L2VPN;
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
	}
	return ret;
}

/*
 * Convert an afi_t/safi_t pair to matching BGP_DEFAULT_AF* flag.
 *
 * afi
 *    address-family identifier
 *
 * safi
 *    subsequent address-family identifier
 *
 * Returns:
 *    default_af string corresponding to the supplied afi/safi pair.
 *    If afi/safi is invalid or if flag for afi/safi doesn't exist,
 *    return -1.
 */
static const char *get_bgp_default_af_flag(afi_t afi, safi_t safi)
{
	switch (afi) {
	case AFI_IP:
		switch (safi) {
		case SAFI_UNICAST:
			return "ipv4-unicast";
		case SAFI_MULTICAST:
			return "ipv4-multicast";
		case SAFI_MPLS_VPN:
			return "ipv4-vpn";
		case SAFI_ENCAP:
			return "ipv4-encap";
		case SAFI_LABELED_UNICAST:
			return "ipv4-labeled-unicast";
		case SAFI_FLOWSPEC:
			return "ipv4-flowspec";
		case SAFI_UNSPEC:
		case SAFI_EVPN:
		case SAFI_MAX:
			return "unknown-afi/safi";
		}
		break;
	case AFI_IP6:
		switch (safi) {
		case SAFI_UNICAST:
			return "ipv6-unicast";
		case SAFI_MULTICAST:
			return "ipv6-multicast";
		case SAFI_MPLS_VPN:
			return "ipv6-vpn";
		case SAFI_ENCAP:
			return "ipv6-encap";
		case SAFI_LABELED_UNICAST:
			return "ipv6-labeled-unicast";
		case SAFI_FLOWSPEC:
			return "ipv6-flowspec";
		case SAFI_UNSPEC:
		case SAFI_EVPN:
		case SAFI_MAX:
			return "unknown-afi/safi";
		}
		break;
	case AFI_L2VPN:
		switch (safi) {
		case SAFI_EVPN:
			return "l2vpn-evpn";
		case SAFI_UNICAST:
		case SAFI_MULTICAST:
		case SAFI_MPLS_VPN:
		case SAFI_ENCAP:
		case SAFI_LABELED_UNICAST:
		case SAFI_FLOWSPEC:
		case SAFI_UNSPEC:
		case SAFI_MAX:
			return "unknown-afi/safi";
		}
		break;
	case AFI_UNSPEC:
	case AFI_MAX:
		return "unknown-afi/safi";
	}
	/* all AFIs are accounted for above, so this shouldn't happen */

	assert(!"Reached end of function where we did not expect to");
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
		if (DFLT_BGP_SOFT_VERSION_CAPABILITY)
			SET_FLAG((*bgp)->flags,
				 BGP_FLAG_SOFT_VERSION_CAPABILITY);
		if (DFLT_BGP_DYNAMIC_CAPABILITY)
			SET_FLAG((*bgp)->flags,
				 BGP_FLAG_DYNAMIC_CAPABILITY);
		if (DFLT_BGP_ENFORCE_FIRST_AS)
			SET_FLAG((*bgp)->flags, BGP_FLAG_ENFORCE_FIRST_AS);

		ret = BGP_SUCCESS;
	}
	return ret;
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
			*bgp = bgp_lookup_by_name(vrf_name);
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

static bool peer_address_self_check(struct bgp *bgp, union sockunion *su)
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

/* Utility function for looking up peer from VTY.  */
/* This is used only for configuration, so disallow if attempted on
 * a dynamic neighbor.
 */
static struct peer *peer_lookup_vty(struct vty *vty, const char *ip_str)
{
	struct bgp *bgp = VTY_GET_CONTEXT(bgp);
	int ret;
	union sockunion su;
	struct peer *peer;

	if (!bgp) {
		return NULL;
	}

	ret = str2sockunion(ip_str, &su);
	if (ret < 0) {
		peer = peer_lookup_by_conf_if(bgp, ip_str);
		if (!peer) {
			if ((peer = peer_lookup_by_hostname(bgp, ip_str))
			    == NULL) {
				vty_out(vty,
					"%% Malformed address or name: %s\n",
					ip_str);
				return NULL;
			}
		}
	} else {
		peer = peer_lookup(bgp, &su);
		if (!peer) {
			vty_out(vty,
				"%% Specify remote-as or peer-group commands first\n");
			return NULL;
		}
		if (peer_dynamic_neighbor(peer)) {
			vty_out(vty,
				"%% Operation not allowed on a dynamic neighbor\n");
			return NULL;
		}
	}
	return peer;
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
	case BGP_ERR_PEER_GROUP_MEMBER:
		str = "Peer-group member cannot override remote-as of peer-group.";
		break;
	case BGP_ERR_PEER_GROUP_PEER_TYPE_DIFFERENT:
		str = "Peer-group members must be all internal or all external.";
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

			if (paf && paf->subgroup)
				SET_FLAG(paf->subgroup->sflags,
					 SUBGRP_STATUS_FORCE_UPDATES);

			tmp_afi = paf->afi;
			tmp_safi = paf->safi;
			if (!peer->afc[tmp_afi][tmp_safi])
				continue;

			if (stype == BGP_CLEAR_SOFT_NONE)
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

			paf = peer_af_find(peer, afi, tmp_safi);
			if (paf && paf->subgroup)
				SET_FLAG(paf->subgroup->sflags,
					 SUBGRP_STATUS_FORCE_UPDATES);

			if (stype == BGP_CLEAR_SOFT_NONE)
				ret = peer_clear(peer, nnode);
			else
				ret = peer_clear_soft(peer, afi,
						      tmp_safi, stype);
		}
	/* both afi/safi specified, let the caller know if not defined */
	} else {
		if (!peer->afc[afi][safi])
			return 1;

		paf = peer_af_find(peer, afi, safi);
		if (paf && paf->subgroup)
			SET_FLAG(paf->subgroup->sflags,
				 SUBGRP_STATUS_FORCE_UPDATES);

		if (stype == BGP_CLEAR_SOFT_NONE)
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

	VTY_BGP_GR_DEFINE_LOOP_VARIABLE;

	/* Clear all neighbors. */
	/*
	 * Pass along pointer to next node to peer_clear() when walking all
	 * nodes on the BGP instance as that may get freed if it is a
	 * doppelganger
	 */
	if (sort == clear_all) {
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
		if (stype == BGP_CLEAR_SOFT_NONE)
			bgp->update_delay_over = 0;

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

		for (ALL_LIST_ELEMENTS(group->peer, node, nnode, peer)) {
			ret = bgp_peer_clear(peer, afi, safi, &nnode, stype);

			if (ret < 0)
				bgp_clear_vty_error(vty, peer, afi, safi, ret);
			else
				found = true;
		}

		if (!found)
			vty_out(vty,
				"%% BGP: No %s peer belonging to peer-group %s is configured\n",
				get_afi_safi_str(afi, safi, false), arg);

		return CMD_SUCCESS;
	}

	/* Clear all external (eBGP) neighbors. */
	if (sort == clear_external) {
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

		if (!found)
			vty_out(vty,
				"%% BGP: No external %s peer is configured\n",
				get_afi_safi_str(afi, safi, false));

		return CMD_SUCCESS;
	}

	/* Clear all neighbors belonging to a specific AS. */
	if (sort == clear_as) {
		as_t as;

		if (!asn_str2asn(arg, &as)) {
			vty_out(vty, "%% BGP: No such AS %s\n", arg);
			return CMD_WARNING;
		}

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

/* clear soft inbound */
static void bgp_clear_star_soft_in(struct vty *vty, const char *name)
{
	afi_t afi;
	safi_t safi;

	FOREACH_AFI_SAFI (afi, safi)
		bgp_clear_vty(vty, name, afi, safi, clear_all,
			      BGP_CLEAR_SOFT_IN, NULL);
}

/* clear soft outbound */
static void bgp_clear_star_soft_out(struct vty *vty, const char *name)
{
	afi_t afi;
	safi_t safi;

	FOREACH_AFI_SAFI (afi, safi)
		bgp_clear_vty(vty, name, afi, safi, clear_all,
			      BGP_CLEAR_SOFT_OUT, NULL);
}


void bgp_clear_soft_in(struct bgp *bgp, afi_t afi, safi_t safi)
{
	bgp_clear(NULL, bgp, afi, safi, clear_all, BGP_CLEAR_SOFT_IN, NULL);
}

static int peer_flag_modify_vty(struct vty *vty, const char *ip_str,
				uint64_t flag, int set)
{
	int ret;
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, ip_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	/*
	 * If 'neighbor <interface>', then this is for directly connected peers,
	 * we should not accept disable-connected-check.
	 */
	if (peer->conf_if && (flag == PEER_FLAG_DISABLE_CONNECTED_CHECK)) {
		vty_out(vty,
			"%s is directly connected peer, cannot accept disable-connected-check\n",
			ip_str);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (!set && flag == PEER_FLAG_SHUTDOWN)
		peer_tx_shutdown_message_unset(peer);

	if (set)
		ret = peer_flag_set(peer, flag);
	else
		ret = peer_flag_unset(peer, flag);

	return bgp_vty_return(vty, ret);
}

static int peer_flag_set_vty(struct vty *vty, const char *ip_str, uint64_t flag)
{
	return peer_flag_modify_vty(vty, ip_str, flag, 1);
}

static int peer_flag_unset_vty(struct vty *vty, const char *ip_str,
			       uint64_t flag)
{
	return peer_flag_modify_vty(vty, ip_str, flag, 0);
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

DEFUN (no_synchronization,
       no_synchronization_cmd,
       "no synchronization",
       NO_STR
       "Perform IGP synchronization\n")
{
	return CMD_SUCCESS;
}

DEFUN (no_auto_summary,
       no_auto_summary_cmd,
       "no auto-summary",
       NO_STR
       "Enable automatic network number summarization\n")
{
	return CMD_SUCCESS;
}

/* "router bgp" commands. */
DEFUN_NOSH (router_bgp,
       router_bgp_cmd,
       "router bgp [ASNUM$instasn [<view|vrf> VIEWVRFNAME] [as-notation <dot|dot+|plain>]]",
       ROUTER_STR
       BGP_STR
       AS_STR
       BGP_INSTANCE_HELP_STR
       "Force the AS notation output\n"
       "use 'AA.BB' format for AS 4 byte values\n"
       "use 'AA.BB' format for all AS values\n"
       "use plain format for all AS values\n")
{
	int idx_asn = 2;
	int idx_view_vrf = 3;
	int idx_vrf = 4;
	int is_new_bgp = 0;
	int idx_asnotation = 3;
	int idx_asnotation_kind = 4;
	enum asnotation_mode asnotation = ASNOTATION_UNDEFINED;
	int ret;
	as_t as;
	struct bgp *bgp;
	const char *name = NULL;
	enum bgp_instance_type inst_type;

	// "router bgp" without an ASN
	if (argc == 2) {
		// Pending: Make VRF option available for ASN less config
		bgp = bgp_get_default();

		if (bgp == NULL) {
			vty_out(vty, "%% No BGP process is configured\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		if (listcount(bm->bgp) > 1) {
			vty_out(vty, "%% Please specify ASN and VRF\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	// "router bgp X"
	else {
		if (!asn_str2asn(argv[idx_asn]->arg, &as)) {
			vty_out(vty, "%% BGP: No such AS %s\n",
				argv[idx_asn]->arg);
			return CMD_WARNING_CONFIG_FAILED;
		}

		if (as == BGP_PRIVATE_AS_MAX || as == BGP_AS4_MAX)
			vty_out(vty, "Reserved AS used (%u|%u); AS is %u\n",
				BGP_PRIVATE_AS_MAX, BGP_AS4_MAX, as);

		inst_type = BGP_INSTANCE_TYPE_DEFAULT;

		if (argv_find(argv, argc, "VIEWVRFNAME", &idx_vrf)) {
			idx_view_vrf = idx_vrf - 1;
			if (argv[idx_view_vrf]->text) {
				name = argv[idx_vrf]->arg;

				if (!strcmp(argv[idx_view_vrf]->text, "vrf")) {
					if (strmatch(name, VRF_DEFAULT_NAME))
						name = NULL;
					else
						inst_type =
							BGP_INSTANCE_TYPE_VRF;
				} else if (!strcmp(argv[idx_view_vrf]->text,
						   "view"))
					inst_type = BGP_INSTANCE_TYPE_VIEW;
			}
		}
		if (argv_find(argv, argc, "as-notation", &idx_asnotation)) {
			idx_asnotation_kind = idx_asnotation + 1;
			if (strmatch(argv[idx_asnotation_kind]->text, "dot+"))
				asnotation = ASNOTATION_DOTPLUS;
			else if (strmatch(argv[idx_asnotation_kind]->text,
					  "dot"))
				asnotation = ASNOTATION_DOT;
			else if (strmatch(argv[idx_asnotation_kind]->text,
					  "plain"))
				asnotation = ASNOTATION_PLAIN;
		}

		if (inst_type == BGP_INSTANCE_TYPE_DEFAULT)
			is_new_bgp = (bgp_lookup(as, name) == NULL);

		ret = bgp_get_vty(&bgp, &as, name, inst_type,
				  argv[idx_asn]->arg, asnotation);
		switch (ret) {
		case BGP_ERR_AS_MISMATCH:
			vty_out(vty, "BGP is already running; AS is %s\n",
				bgp->as_pretty);
			return CMD_WARNING_CONFIG_FAILED;
		case BGP_ERR_INSTANCE_MISMATCH:
			vty_out(vty,
				"BGP instance name and AS number mismatch\n");
			vty_out(vty,
				"BGP instance is already running; AS is %s\n",
				bgp->as_pretty);
			return CMD_WARNING_CONFIG_FAILED;
		}

		/*
		 * If we just instantiated the default instance, complete
		 * any pending VRF-VPN leaking that was configured via
		 * earlier "router bgp X vrf FOO" blocks.
		 */
		if (is_new_bgp && inst_type == BGP_INSTANCE_TYPE_DEFAULT)
			vpn_leak_postchange_all();

		if (inst_type == BGP_INSTANCE_TYPE_VRF ||
		    IS_BGP_INSTANCE_HIDDEN(bgp)) {
			bgp_vpn_leak_export(bgp);
			UNSET_FLAG(bgp->flags, BGP_FLAG_INSTANCE_HIDDEN);
			UNSET_FLAG(bgp->flags, BGP_FLAG_DELETE_IN_PROGRESS);
		}
		/* Pending: handle when user tries to change a view to vrf n vv.
		 */
		/* for pre-existing bgp instance,
		 * - update as_pretty
		 * - update asnotation if explicitly mentioned
		 */
		if (CHECK_FLAG(bgp->vrf_flags, BGP_VRF_AUTO)) {
			XFREE(MTYPE_BGP_NAME, bgp->as_pretty);
			bgp->as_pretty = XSTRDUP(MTYPE_BGP_NAME,
						 argv[idx_asn]->arg);
			if (!CHECK_FLAG(bgp->config, BGP_CONFIG_ASNOTATION) &&
			    asnotation != ASNOTATION_UNDEFINED) {
				SET_FLAG(bgp->config, BGP_CONFIG_ASNOTATION);
				bgp->asnotation = asnotation;
			}
		}
	}

	/* unset the auto created flag as the user config is now present */
	UNSET_FLAG(bgp->vrf_flags, BGP_VRF_AUTO);
	VTY_PUSH_CONTEXT(BGP_NODE, bgp);

	return CMD_SUCCESS;
}

/* "no router bgp" commands. */
DEFUN (no_router_bgp,
       no_router_bgp_cmd,
       "no router bgp [ASNUM$instasn [<view|vrf> VIEWVRFNAME] [as-notation <dot|dot+|plain>]]",
       NO_STR
       ROUTER_STR
       BGP_STR
       AS_STR
       BGP_INSTANCE_HELP_STR
       "Force the AS notation output\n"
       "use 'AA.BB' format for AS 4 byte values\n"
       "use 'AA.BB' format for all AS values\n"
       "use plain format for all AS values\n")
{
	int idx_asn = 3;
	int idx_vrf = 5;
	as_t as;
	struct bgp *bgp;
	const char *name = NULL;

	// "no router bgp" without an ASN
	if (argc == 3) {
		// Pending: Make VRF option available for ASN less config
		bgp = bgp_get_default();

		if (bgp == NULL) {
			vty_out(vty, "%% No BGP process is configured\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		if (listcount(bm->bgp) > 1) {
			vty_out(vty, "%% Please specify ASN and VRF\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		if (bgp->l3vni) {
			vty_out(vty, "%% Please unconfigure l3vni %u\n",
				bgp->l3vni);
			return CMD_WARNING_CONFIG_FAILED;
		}
	} else {
		if (!asn_str2asn(argv[idx_asn]->arg, &as)) {
			vty_out(vty, "%% BGP: No such AS %s\n",
				argv[idx_asn]->arg);
			return CMD_WARNING_CONFIG_FAILED;
		}
		if (argc > 4 && strncmp(argv[4]->arg, "vrf", 3) == 0) {
			name = argv[idx_vrf]->arg;
			if (strmatch(argv[idx_vrf - 1]->text, "vrf")
			    && strmatch(name, VRF_DEFAULT_NAME))
				name = NULL;
		}

		/* Lookup bgp structure. */
		bgp = bgp_lookup(as, name);
		if (!bgp) {
			vty_out(vty, "%% Can't find BGP instance\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		if (bgp->l3vni) {
			vty_out(vty, "%% Please unconfigure l3vni %u\n",
				bgp->l3vni);
			return CMD_WARNING_CONFIG_FAILED;
		}

		/* Cannot delete default instance if vrf instances exist */
		if (bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT) {
			struct listnode *node, *nnode;
			struct bgp *tmp_bgp;

			for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, tmp_bgp)) {
				if (tmp_bgp->inst_type != BGP_INSTANCE_TYPE_VRF)
					continue;

				if (CHECK_FLAG(tmp_bgp->vrf_flags,
					       BGP_VRF_AUTO)) {
					bgp_delete(tmp_bgp);
					continue;
				}

				if (CHECK_FLAG(
					    tmp_bgp->af_flags[AFI_IP]
							     [SAFI_UNICAST],
					    BGP_CONFIG_MPLSVPN_TO_VRF_IMPORT) ||
				    CHECK_FLAG(
					    tmp_bgp->af_flags[AFI_IP6]
							     [SAFI_UNICAST],
					    BGP_CONFIG_MPLSVPN_TO_VRF_IMPORT) ||
				    CHECK_FLAG(
					    tmp_bgp->af_flags[AFI_IP]
							     [SAFI_UNICAST],
					    BGP_CONFIG_VRF_TO_MPLSVPN_EXPORT) ||
				    CHECK_FLAG(
					    tmp_bgp->af_flags[AFI_IP6]
							     [SAFI_UNICAST],
					    BGP_CONFIG_VRF_TO_MPLSVPN_EXPORT) ||
				    CHECK_FLAG(tmp_bgp->af_flags[AFI_IP]
								[SAFI_UNICAST],
					       BGP_CONFIG_VRF_TO_VRF_EXPORT) ||
				    CHECK_FLAG(tmp_bgp->af_flags[AFI_IP6]
								[SAFI_UNICAST],
					       BGP_CONFIG_VRF_TO_VRF_EXPORT) ||
				    (bgp == bgp_get_evpn() &&
				     (CHECK_FLAG(
					      tmp_bgp->af_flags[AFI_L2VPN]
							       [SAFI_EVPN],
					      BGP_L2VPN_EVPN_ADV_IPV4_UNICAST) ||
				      CHECK_FLAG(
					      tmp_bgp->af_flags[AFI_L2VPN]
							       [SAFI_EVPN],
					      BGP_L2VPN_EVPN_ADV_IPV4_UNICAST_GW_IP) ||
				      CHECK_FLAG(
					      tmp_bgp->af_flags[AFI_L2VPN]
							       [SAFI_EVPN],
					      BGP_L2VPN_EVPN_ADV_IPV6_UNICAST) ||
				      CHECK_FLAG(
					      tmp_bgp->af_flags[AFI_L2VPN]
							       [SAFI_EVPN],
					      BGP_L2VPN_EVPN_ADV_IPV6_UNICAST_GW_IP))) ||
				    (tmp_bgp->l3vni)) {
					vty_out(vty,
						"%% Cannot delete default BGP instance. Dependent VRF instances exist\n");
					return CMD_WARNING_CONFIG_FAILED;
				}
			}
		}
	}

	bgp_delete(bgp);

	return CMD_SUCCESS;
}

/* bgp session-dscp */

DEFPY (bgp_session_dscp,
       bgp_session_dscp_cmd,
       "bgp session-dscp (0-63)$dscp",
       BGP_STR
       "Override default (CS6) DSCP for BGP connections\n"
       "Manually configured DSCP value\n")
{
	bm->ip_tos = dscp << 2;

	return CMD_SUCCESS;
}

DEFPY (no_bgp_session_dscp,
       no_bgp_session_dscp_cmd,
       "no bgp session-dscp [(0-63)]",
       NO_STR
       BGP_STR
       "Override default (CS6) DSCP for BGP connections\n"
       "Manually configured DSCP value\n")
{
	bm->ip_tos = IPTOS_PREC_INTERNETCONTROL;

	return CMD_SUCCESS;
}

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

DEFPY (no_bgp_router_id,
       no_bgp_router_id_cmd,
       "no bgp router-id [A.B.C.D]",
       NO_STR
       BGP_STR
       "Override configured router identifier\n"
       "Manually configured router identifier\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	if (router_id_str) {
		if (!IPV4_ADDR_SAME(&bgp->router_id_static, &router_id)) {
			vty_out(vty, "%% BGP router-id doesn't match\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	router_id.s_addr = 0;
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

DEFPY (bgp_global_suppress_fib_pending,
       bgp_global_suppress_fib_pending_cmd,
       "[no] bgp suppress-fib-pending",
       NO_STR
       BGP_STR
       "Advertise only routes that are programmed in kernel to peers globally\n")
{
	bm_wait_for_fib_set(!no);

	return CMD_SUCCESS;
}

DEFPY (bgp_suppress_fib_pending,
       bgp_suppress_fib_pending_cmd,
       "[no] bgp suppress-fib-pending",
       NO_STR
       BGP_STR
       "Advertise only routes that are programmed in kernel to peers\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	bgp_suppress_fib_pending_set(bgp, !no);
	return CMD_SUCCESS;
}

/* BGP Cluster ID.  */
DEFUN (bgp_cluster_id,
       bgp_cluster_id_cmd,
       "bgp cluster-id <A.B.C.D|(1-4294967295)>",
       BGP_STR
       "Configure Route-Reflector Cluster-id\n"
       "Route-Reflector Cluster-id in IP address format\n"
       "Route-Reflector Cluster-id as 32 bit quantity\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_ipv4 = 2;
	int ret;
	struct in_addr cluster;

	ret = inet_aton(argv[idx_ipv4]->arg, &cluster);
	if (!ret) {
		vty_out(vty, "%% Malformed bgp cluster identifier\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	bgp_cluster_id_set(bgp, &cluster);
	bgp_clear_star_soft_out(vty, bgp->name);

	return CMD_SUCCESS;
}

DEFUN (no_bgp_cluster_id,
       no_bgp_cluster_id_cmd,
       "no bgp cluster-id [<A.B.C.D|(1-4294967295)>]",
       NO_STR
       BGP_STR
       "Configure Route-Reflector Cluster-id\n"
       "Route-Reflector Cluster-id in IP address format\n"
       "Route-Reflector Cluster-id as 32 bit quantity\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	bgp_cluster_id_unset(bgp);
	bgp_clear_star_soft_out(vty, bgp->name);

	return CMD_SUCCESS;
}

DEFPY (bgp_norib,
       bgp_norib_cmd,
       "bgp no-rib",
       BGP_STR
       "Disable BGP route installation to RIB (Zebra)\n")
{
	if (bgp_option_check(BGP_OPT_NO_FIB)) {
		vty_out(vty,
			"%% No-RIB option is already set, nothing to do here.\n");
		return CMD_SUCCESS;
	}

	bgp_option_norib_set_runtime();

	return CMD_SUCCESS;
}

DEFPY (no_bgp_norib,
       no_bgp_norib_cmd,
       "no bgp no-rib",
       NO_STR
       BGP_STR
       "Disable BGP route installation to RIB (Zebra)\n")
{
	if (!bgp_option_check(BGP_OPT_NO_FIB)) {
		vty_out(vty,
			"%% No-RIB option is not set, nothing to do here.\n");
		return CMD_SUCCESS;
	}

	bgp_option_norib_unset_runtime();

	return CMD_SUCCESS;
}

DEFPY (no_bgp_send_extra_data,
       no_bgp_send_extra_data_cmd,
       "[no] bgp send-extra-data zebra",
       NO_STR
       BGP_STR
       "Extra data to Zebra for display/use\n"
       "To zebra\n")
{
	if (no)
		UNSET_FLAG(bm->flags, BM_FLAG_SEND_EXTRA_DATA_TO_ZEBRA);
	else
		SET_FLAG(bm->flags, BM_FLAG_SEND_EXTRA_DATA_TO_ZEBRA);

	return CMD_SUCCESS;
}

DEFUN (bgp_confederation_identifier,
       bgp_confederation_identifier_cmd,
       "bgp confederation identifier ASNUM",
       BGP_STR
       "AS confederation parameters\n"
       "Set routing domain confederation AS\n"
       AS_STR)
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_number = 3;
	as_t as;

	if (!asn_str2asn(argv[idx_number]->arg, &as)) {
		vty_out(vty, "%% BGP: No such AS %s\n", argv[idx_number]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	bgp_confederation_id_set(bgp, as, argv[idx_number]->arg);

	return CMD_SUCCESS;
}

DEFUN (no_bgp_confederation_identifier,
       no_bgp_confederation_identifier_cmd,
       "no bgp confederation identifier [ASNUM]",
       NO_STR
       BGP_STR
       "AS confederation parameters\n"
       "Set routing domain confederation AS\n"
       AS_STR)
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	bgp_confederation_id_unset(bgp);

	return CMD_SUCCESS;
}

DEFUN (bgp_confederation_peers,
       bgp_confederation_peers_cmd,
       "bgp confederation peers ASNUM...",
       BGP_STR
       "AS confederation parameters\n"
       "Peer ASs in BGP confederation\n"
       AS_STR)
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_asn = 3;
	as_t as;
	int i;

	for (i = idx_asn; i < argc; i++) {
		if (!asn_str2asn(argv[i]->arg, &as)) {
			vty_out(vty, "%% Invalid confed peer AS value: %s\n",
				argv[i]->arg);
			continue;
		}

		bgp_confederation_peers_add(bgp, as, argv[i]->arg);
	}
	return CMD_SUCCESS;
}

DEFUN (no_bgp_confederation_peers,
       no_bgp_confederation_peers_cmd,
       "no bgp confederation peers ASNUM...",
       NO_STR
       BGP_STR
       "AS confederation parameters\n"
       "Peer ASs in BGP confederation\n"
       AS_STR)
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_asn = 4;
	as_t as;
	int i;

	for (i = idx_asn; i < argc; i++) {
		if (!asn_str2asn(argv[i]->arg, &as)) {
			vty_out(vty, "%% Invalid confed peer AS value: %s\n",
				argv[i]->arg);
			continue;
		}
		bgp_confederation_peers_remove(bgp, as);
	}
	return CMD_SUCCESS;
}

/**
 * Central routine for maximum-paths configuration.
 * @peer_type: BGP_PEER_EBGP or BGP_PEER_IBGP
 * @set: 1 for setting values, 0 for removing the max-paths config.
 */
static int bgp_maxpaths_config_vty(struct vty *vty, int peer_type,
				   const char *mpaths, uint16_t options,
				   int set)
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	uint16_t maxpaths = 0;
	int ret;
	afi_t afi;
	safi_t safi;

	afi = bgp_node_afi(vty);
	safi = bgp_node_safi(vty);

	if (set) {
		maxpaths = strtol(mpaths, NULL, 10);
		if (maxpaths > multipath_num) {
			vty_out(vty,
				"%% Maxpaths Specified: %d is > than multipath num specified on bgp command line %d",
				maxpaths, multipath_num);
			return CMD_WARNING_CONFIG_FAILED;
		}
		ret = bgp_maximum_paths_set(bgp, afi, safi, peer_type, maxpaths,
					    options);
	} else
		ret = bgp_maximum_paths_unset(bgp, afi, safi, peer_type);

	if (ret < 0) {
		vty_out(vty,
			"%% Failed to %sset maximum-paths %s %u for afi %u, safi %u\n",
			(set == 1) ? "" : "un",
			(peer_type == BGP_PEER_EBGP) ? "ebgp" : "ibgp",
			maxpaths, afi, safi);
		return CMD_WARNING_CONFIG_FAILED;
	}

	bgp_recalculate_all_bestpaths(bgp);

	return CMD_SUCCESS;
}

DEFUN (bgp_maxmed_admin,
       bgp_maxmed_admin_cmd,
       "bgp max-med administrative ",
       BGP_STR
       "Advertise routes with max-med\n"
       "Administratively applied, for an indefinite period\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	bgp->v_maxmed_admin = 1;
	bgp->maxmed_admin_value = BGP_MAXMED_VALUE_DEFAULT;

	bgp_maxmed_update(bgp);

	return CMD_SUCCESS;
}

DEFUN (bgp_maxmed_admin_medv,
       bgp_maxmed_admin_medv_cmd,
       "bgp max-med administrative (0-4294967295)",
       BGP_STR
       "Advertise routes with max-med\n"
       "Administratively applied, for an indefinite period\n"
       "Max MED value to be used\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_number = 3;

	bgp->v_maxmed_admin = 1;
	bgp->maxmed_admin_value = strtoul(argv[idx_number]->arg, NULL, 10);

	bgp_maxmed_update(bgp);

	return CMD_SUCCESS;
}

DEFUN (no_bgp_maxmed_admin,
       no_bgp_maxmed_admin_cmd,
       "no bgp max-med administrative [(0-4294967295)]",
       NO_STR
       BGP_STR
       "Advertise routes with max-med\n"
       "Administratively applied, for an indefinite period\n"
       "Max MED value to be used\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	bgp->v_maxmed_admin = BGP_MAXMED_ADMIN_UNCONFIGURED;
	bgp->maxmed_admin_value = BGP_MAXMED_VALUE_DEFAULT;
	bgp_maxmed_update(bgp);

	return CMD_SUCCESS;
}

DEFUN (bgp_maxmed_onstartup,
       bgp_maxmed_onstartup_cmd,
       "bgp max-med on-startup (5-86400) [(0-4294967295)]",
       BGP_STR
       "Advertise routes with max-med\n"
       "Effective on a startup\n"
       "Time (seconds) period for max-med\n"
       "Max MED value to be used\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx = 0;

	if (argv_find(argv, argc, "(5-86400)", &idx))
		bgp->v_maxmed_onstartup = strtoul(argv[idx]->arg, NULL, 10);
	if (argv_find(argv, argc, "(0-4294967295)", &idx))
		bgp->maxmed_onstartup_value = strtoul(argv[idx]->arg, NULL, 10);
	else
		bgp->maxmed_onstartup_value = BGP_MAXMED_VALUE_DEFAULT;

	bgp_maxmed_update(bgp);

	return CMD_SUCCESS;
}

DEFUN (no_bgp_maxmed_onstartup,
       no_bgp_maxmed_onstartup_cmd,
       "no bgp max-med on-startup [(5-86400) [(0-4294967295)]]",
       NO_STR
       BGP_STR
       "Advertise routes with max-med\n"
       "Effective on a startup\n"
       "Time (seconds) period for max-med\n"
       "Max MED value to be used\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	/* Cancel max-med onstartup if its on */
	if (bgp->t_maxmed_onstartup) {
		EVENT_OFF(bgp->t_maxmed_onstartup);
		bgp->maxmed_onstartup_over = 1;
	}

	bgp->v_maxmed_onstartup = BGP_MAXMED_ONSTARTUP_UNCONFIGURED;
	bgp->maxmed_onstartup_value = BGP_MAXMED_VALUE_DEFAULT;

	bgp_maxmed_update(bgp);

	return CMD_SUCCESS;
}

static int bgp_global_update_delay_config_vty(struct vty *vty,
					      uint16_t update_delay,
					      uint16_t establish_wait)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;
	bool vrf_cfg = false;

	/*
	 * See if update-delay is set per-vrf and warn user to delete it
	 * Note that we only need to check this if this is the first time
	 * setting the global config.
	 */
	if (bm->v_update_delay == BGP_UPDATE_DELAY_DEFAULT) {
		for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
			if (bgp->v_update_delay != BGP_UPDATE_DELAY_DEFAULT) {
				vty_out(vty,
					"%% update-delay configuration found in vrf %s\n",
					bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT
						? VRF_DEFAULT_NAME
						: bgp->name);
				vrf_cfg = true;
			}
		}
	}

	if (vrf_cfg) {
		vty_out(vty,
			"%%Failed: global update-delay config not permitted\n");
		return CMD_WARNING;
	}

	if (!establish_wait) { /* update-delay <delay> */
		bm->v_update_delay = update_delay;
		bm->v_establish_wait = bm->v_update_delay;
	} else {
		/* update-delay <delay> <establish-wait> */
		if (update_delay < establish_wait) {
			vty_out(vty,
				"%%Failed: update-delay less than the establish-wait!\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		bm->v_update_delay = update_delay;
		bm->v_establish_wait = establish_wait;
	}

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		bgp->v_update_delay = bm->v_update_delay;
		bgp->v_establish_wait = bm->v_establish_wait;
	}

	return CMD_SUCCESS;
}

static int bgp_global_update_delay_deconfig_vty(struct vty *vty)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;

	bm->v_update_delay = BGP_UPDATE_DELAY_DEFAULT;
	bm->v_establish_wait = bm->v_update_delay;

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		bgp->v_update_delay = bm->v_update_delay;
		bgp->v_establish_wait = bm->v_establish_wait;
	}

	return CMD_SUCCESS;
}

static int bgp_update_delay_config_vty(struct vty *vty, uint16_t update_delay,
				       uint16_t establish_wait)
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	/* if configured globally, per-instance config is not allowed */
	if (bm->v_update_delay) {
		vty_out(vty,
			"%%Failed: per-vrf update-delay config not permitted with global update-delay\n");
		return CMD_WARNING_CONFIG_FAILED;
	}


	if (!establish_wait) /* update-delay <delay> */
	{
		bgp->v_update_delay = update_delay;
		bgp->v_establish_wait = bgp->v_update_delay;
		return CMD_SUCCESS;
	}

	/* update-delay <delay> <establish-wait> */
	if (update_delay < establish_wait) {
		vty_out(vty,
			"%%Failed: update-delay less than the establish-wait!\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	bgp->v_update_delay = update_delay;
	bgp->v_establish_wait = establish_wait;

	return CMD_SUCCESS;
}

static int bgp_update_delay_deconfig_vty(struct vty *vty)
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	/* If configured globally, cannot remove from one bgp instance */
	if (bm->v_update_delay) {
		vty_out(vty,
			"%%Failed: bgp update-delay configured globally. Delete per-vrf not permitted\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	bgp->v_update_delay = BGP_UPDATE_DELAY_DEFAULT;
	bgp->v_establish_wait = bgp->v_update_delay;

	return CMD_SUCCESS;
}

void bgp_config_write_update_delay(struct vty *vty, struct bgp *bgp)
{
	/* If configured globally, no need to display per-instance value */
	if (bgp->v_update_delay != bm->v_update_delay) {
		vty_out(vty, " update-delay %d", bgp->v_update_delay);
		if (bgp->v_update_delay != bgp->v_establish_wait)
			vty_out(vty, " %d", bgp->v_establish_wait);
		vty_out(vty, "\n");
	}
}

/* Global update-delay configuration */
DEFPY (bgp_global_update_delay,
       bgp_global_update_delay_cmd,
       "bgp update-delay (0-3600)$delay [(1-3600)$wait]",
       BGP_STR
       "Force initial delay for best-path and updates for all bgp instances\n"
       "Max delay in seconds\n"
       "Establish wait in seconds\n")
{
	return bgp_global_update_delay_config_vty(vty, delay, wait);
}

/* Global update-delay deconfiguration */
DEFPY (no_bgp_global_update_delay,
       no_bgp_global_update_delay_cmd,
       "no bgp update-delay [(0-3600) [(1-3600)]]",
       NO_STR
       BGP_STR
       "Force initial delay for best-path and updates\n"
       "Max delay in seconds\n"
       "Establish wait in seconds\n")
{
	return bgp_global_update_delay_deconfig_vty(vty);
}

/* Update-delay configuration */

DEFPY (bgp_update_delay,
       bgp_update_delay_cmd,
       "update-delay (0-3600)$delay [(1-3600)$wait]",
       "Force initial delay for best-path and updates\n"
       "Max delay in seconds\n"
       "Establish wait in seconds\n")
{
	return bgp_update_delay_config_vty(vty, delay, wait);
}

/* Update-delay deconfiguration */
DEFPY (no_bgp_update_delay,
       no_bgp_update_delay_cmd,
       "no update-delay [(0-3600) [(1-3600)]]",
       NO_STR
       "Force initial delay for best-path and updates\n"
       "Max delay in seconds\n"
       "Establish wait in seconds\n")
{
	return bgp_update_delay_deconfig_vty(vty);
}


static int bgp_wpkt_quanta_config_vty(struct vty *vty, uint32_t quanta,
				      bool set)
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	quanta = set ? quanta : BGP_WRITE_PACKET_MAX;
	atomic_store_explicit(&bgp->wpkt_quanta, quanta, memory_order_relaxed);

	return CMD_SUCCESS;
}

static int bgp_rpkt_quanta_config_vty(struct vty *vty, uint32_t quanta,
				      bool set)
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	quanta = set ? quanta : BGP_READ_PACKET_MAX;
	atomic_store_explicit(&bgp->rpkt_quanta, quanta, memory_order_relaxed);

	return CMD_SUCCESS;
}

void bgp_config_write_wpkt_quanta(struct vty *vty, struct bgp *bgp)
{
	uint32_t quanta =
		atomic_load_explicit(&bgp->wpkt_quanta, memory_order_relaxed);
	if (quanta != BGP_WRITE_PACKET_MAX)
		vty_out(vty, " write-quanta %d\n", quanta);
}

void bgp_config_write_rpkt_quanta(struct vty *vty, struct bgp *bgp)
{
	uint32_t quanta =
		atomic_load_explicit(&bgp->rpkt_quanta, memory_order_relaxed);
	if (quanta != BGP_READ_PACKET_MAX)
		vty_out(vty, " read-quanta %d\n", quanta);
}

/* Packet quanta configuration
 *
 * XXX: The value set here controls the size of a stack buffer in the IO
 * thread. When changing these limits be careful to prevent stack overflow.
 *
 * Furthermore, the maximums used here should correspond to
 * BGP_WRITE_PACKET_MAX and BGP_READ_PACKET_MAX.
 */
DEFPY (bgp_wpkt_quanta,
       bgp_wpkt_quanta_cmd,
       "[no] write-quanta (1-64)$quanta",
       NO_STR
       "How many packets to write to peer socket per run\n"
       "Number of packets\n")
{
	return bgp_wpkt_quanta_config_vty(vty, quanta, !no);
}

DEFPY (bgp_rpkt_quanta,
       bgp_rpkt_quanta_cmd,
       "[no] read-quanta (1-10)$quanta",
       NO_STR
       "How many packets to read from peer socket per I/O cycle\n"
       "Number of packets\n")
{
	return bgp_rpkt_quanta_config_vty(vty, quanta, !no);
}

void bgp_config_write_coalesce_time(struct vty *vty, struct bgp *bgp)
{
	if (!bgp->heuristic_coalesce)
		vty_out(vty, " coalesce-time %u\n", bgp->coalesce_time);
}

/* BGP TCP keepalive */
static void bgp_config_tcp_keepalive(struct vty *vty, struct bgp *bgp)
{
	if (bgp->tcp_keepalive_idle) {
		vty_out(vty, " bgp tcp-keepalive %u %u %u\n",
			bgp->tcp_keepalive_idle, bgp->tcp_keepalive_intvl,
			bgp->tcp_keepalive_probes);
	}
}

DEFUN (bgp_coalesce_time,
       bgp_coalesce_time_cmd,
       "coalesce-time (0-4294967295)",
       "Subgroup coalesce timer\n"
       "Subgroup coalesce timer value (in ms)\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	int idx = 0;

	bgp->heuristic_coalesce = false;

	if (argv_find(argv, argc, "(0-4294967295)", &idx))
		bgp->coalesce_time = strtoul(argv[idx]->arg, NULL, 10);

	return CMD_SUCCESS;
}

DEFUN (no_bgp_coalesce_time,
       no_bgp_coalesce_time_cmd,
       "no coalesce-time (0-4294967295)",
       NO_STR
       "Subgroup coalesce timer\n"
       "Subgroup coalesce timer value (in ms)\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	bgp->heuristic_coalesce = true;
	bgp->coalesce_time = BGP_DEFAULT_SUBGROUP_COALESCE_TIME;
	return CMD_SUCCESS;
}

/* Maximum-paths configuration */
DEFUN (bgp_maxpaths,
       bgp_maxpaths_cmd,
       "maximum-paths " CMD_RANGE_STR(1, MULTIPATH_NUM),
       "Forward packets over multiple paths\n"
       "Number of paths\n")
{
	int idx_number = 1;
	return bgp_maxpaths_config_vty(vty, BGP_PEER_EBGP,
				       argv[idx_number]->arg, 0, 1);
}

ALIAS_HIDDEN(bgp_maxpaths, bgp_maxpaths_hidden_cmd,
	     "maximum-paths " CMD_RANGE_STR(1, MULTIPATH_NUM),
	     "Forward packets over multiple paths\n"
	     "Number of paths\n")

DEFUN (bgp_maxpaths_ibgp,
       bgp_maxpaths_ibgp_cmd,
       "maximum-paths ibgp " CMD_RANGE_STR(1, MULTIPATH_NUM),
       "Forward packets over multiple paths\n"
       "iBGP-multipath\n"
       "Number of paths\n")
{
	int idx_number = 2;
	return bgp_maxpaths_config_vty(vty, BGP_PEER_IBGP,
				       argv[idx_number]->arg, 0, 1);
}

ALIAS_HIDDEN(bgp_maxpaths_ibgp, bgp_maxpaths_ibgp_hidden_cmd,
	     "maximum-paths ibgp " CMD_RANGE_STR(1, MULTIPATH_NUM),
	     "Forward packets over multiple paths\n"
	     "iBGP-multipath\n"
	     "Number of paths\n")

DEFUN (bgp_maxpaths_ibgp_cluster,
       bgp_maxpaths_ibgp_cluster_cmd,
       "maximum-paths ibgp " CMD_RANGE_STR(1, MULTIPATH_NUM) " equal-cluster-length",
       "Forward packets over multiple paths\n"
       "iBGP-multipath\n"
       "Number of paths\n"
       "Match the cluster length\n")
{
	int idx_number = 2;
	return bgp_maxpaths_config_vty(vty, BGP_PEER_IBGP,
				       argv[idx_number]->arg, true, 1);
}

ALIAS_HIDDEN(bgp_maxpaths_ibgp_cluster, bgp_maxpaths_ibgp_cluster_hidden_cmd,
	     "maximum-paths ibgp " CMD_RANGE_STR(
		     1, MULTIPATH_NUM) " equal-cluster-length",
	     "Forward packets over multiple paths\n"
	     "iBGP-multipath\n"
	     "Number of paths\n"
	     "Match the cluster length\n")

DEFUN (no_bgp_maxpaths,
       no_bgp_maxpaths_cmd,
       "no maximum-paths [" CMD_RANGE_STR(1, MULTIPATH_NUM) "]",
       NO_STR
       "Forward packets over multiple paths\n"
       "Number of paths\n")
{
	return bgp_maxpaths_config_vty(vty, BGP_PEER_EBGP, NULL, 0, 0);
}

ALIAS_HIDDEN(no_bgp_maxpaths, no_bgp_maxpaths_hidden_cmd,
	     "no maximum-paths [" CMD_RANGE_STR(1, MULTIPATH_NUM) "]", NO_STR
	     "Forward packets over multiple paths\n"
	     "Number of paths\n")

DEFUN (no_bgp_maxpaths_ibgp,
       no_bgp_maxpaths_ibgp_cmd,
       "no maximum-paths ibgp [" CMD_RANGE_STR(1, MULTIPATH_NUM) " [equal-cluster-length]]",
       NO_STR
       "Forward packets over multiple paths\n"
       "iBGP-multipath\n"
       "Number of paths\n"
       "Match the cluster length\n")
{
	return bgp_maxpaths_config_vty(vty, BGP_PEER_IBGP, NULL, 0, 0);
}

ALIAS_HIDDEN(no_bgp_maxpaths_ibgp, no_bgp_maxpaths_ibgp_hidden_cmd,
	     "no maximum-paths ibgp [" CMD_RANGE_STR(
		     1, MULTIPATH_NUM) " [equal-cluster-length]]",
	     NO_STR
	     "Forward packets over multiple paths\n"
	     "iBGP-multipath\n"
	     "Number of paths\n"
	     "Match the cluster length\n")

static void bgp_config_write_maxpaths(struct vty *vty, struct bgp *bgp,
				      afi_t afi, safi_t safi)
{
	if (bgp->maxpaths[afi][safi].maxpaths_ebgp != multipath_num) {
		vty_out(vty, "  maximum-paths %d\n",
			bgp->maxpaths[afi][safi].maxpaths_ebgp);
	}

	if (bgp->maxpaths[afi][safi].maxpaths_ibgp != multipath_num) {
		vty_out(vty, "  maximum-paths ibgp %d",
			bgp->maxpaths[afi][safi].maxpaths_ibgp);
		if (bgp->maxpaths[afi][safi].same_clusterlen)
			vty_out(vty, " equal-cluster-length");
		vty_out(vty, "\n");
	}
}

/* BGP timers.  */

DEFUN (bgp_timers,
       bgp_timers_cmd,
       "timers bgp (0-65535) (0-65535)",
       "Adjust routing timers\n"
       "BGP timers\n"
       "Keepalive interval\n"
       "Holdtime\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_number = 2;
	int idx_number_2 = 3;
	unsigned long keepalive = 0;
	unsigned long holdtime = 0;

	keepalive = strtoul(argv[idx_number]->arg, NULL, 10);
	holdtime = strtoul(argv[idx_number_2]->arg, NULL, 10);

	/* Holdtime value check. */
	if (holdtime < 3 && holdtime != 0) {
		vty_out(vty,
			"%% hold time value must be either 0 or greater than 3\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	bgp_timers_set(vty, bgp, keepalive, holdtime, DFLT_BGP_CONNECT_RETRY,
		       BGP_DEFAULT_DELAYOPEN);

	return CMD_SUCCESS;
}

DEFUN (no_bgp_timers,
       no_bgp_timers_cmd,
       "no timers bgp [(0-65535) (0-65535)]",
       NO_STR
       "Adjust routing timers\n"
       "BGP timers\n"
       "Keepalive interval\n"
       "Holdtime\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	bgp_timers_set(vty, bgp, DFLT_BGP_KEEPALIVE, DFLT_BGP_HOLDTIME,
		       DFLT_BGP_CONNECT_RETRY, BGP_DEFAULT_DELAYOPEN);

	return CMD_SUCCESS;
}

/* BGP minimum holdtime.  */

DEFUN(bgp_minimum_holdtime, bgp_minimum_holdtime_cmd,
      "bgp minimum-holdtime (1-65535)",
      "BGP specific commands\n"
      "BGP minimum holdtime\n"
      "Seconds\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_number = 2;
	unsigned long min_holdtime;

	min_holdtime = strtoul(argv[idx_number]->arg, NULL, 10);

	bgp->default_min_holdtime = min_holdtime;

	return CMD_SUCCESS;
}

DEFUN(no_bgp_minimum_holdtime, no_bgp_minimum_holdtime_cmd,
      "no bgp minimum-holdtime [(1-65535)]",
      NO_STR
      "BGP specific commands\n"
      "BGP minimum holdtime\n"
      "Seconds\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	bgp->default_min_holdtime = 0;

	return CMD_SUCCESS;
}

DEFPY(bgp_tcp_keepalive, bgp_tcp_keepalive_cmd,
      "bgp tcp-keepalive (1-65535)$idle (1-65535)$intvl (1-30)$probes",
      BGP_STR
      "TCP keepalive parameters\n"
      "TCP keepalive idle time (seconds)\n"
      "TCP keepalive interval (seconds)\n"
      "TCP keepalive maximum probes\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	bgp_tcp_keepalive_set(bgp, (uint16_t)idle, (uint16_t)intvl,
			      (uint16_t)probes);

	return CMD_SUCCESS;
}

DEFPY(no_bgp_tcp_keepalive, no_bgp_tcp_keepalive_cmd,
      "no bgp tcp-keepalive [(1-65535) (1-65535) (1-30)]",
      NO_STR
      BGP_STR
      "TCP keepalive parameters\n"
      "TCP keepalive idle time (seconds)\n"
      "TCP keepalive interval (seconds)\n"
      "TCP keepalive maximum probes\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	bgp_tcp_keepalive_unset(bgp);

	return CMD_SUCCESS;
}

DEFUN (bgp_client_to_client_reflection,
       bgp_client_to_client_reflection_cmd,
       "bgp client-to-client reflection",
       BGP_STR
       "Configure client to client route reflection\n"
       "reflection of routes allowed\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	UNSET_FLAG(bgp->flags, BGP_FLAG_NO_CLIENT_TO_CLIENT);
	bgp_clear_star_soft_out(vty, bgp->name);

	return CMD_SUCCESS;
}

DEFUN (no_bgp_client_to_client_reflection,
       no_bgp_client_to_client_reflection_cmd,
       "no bgp client-to-client reflection",
       NO_STR
       BGP_STR
       "Configure client to client route reflection\n"
       "reflection of routes allowed\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	SET_FLAG(bgp->flags, BGP_FLAG_NO_CLIENT_TO_CLIENT);
	bgp_clear_star_soft_out(vty, bgp->name);

	return CMD_SUCCESS;
}

/* "bgp always-compare-med" configuration. */
DEFUN (bgp_always_compare_med,
       bgp_always_compare_med_cmd,
       "bgp always-compare-med",
       BGP_STR
       "Allow comparing MED from different neighbors\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	SET_FLAG(bgp->flags, BGP_FLAG_ALWAYS_COMPARE_MED);
	bgp_recalculate_all_bestpaths(bgp);

	return CMD_SUCCESS;
}

DEFUN (no_bgp_always_compare_med,
       no_bgp_always_compare_med_cmd,
       "no bgp always-compare-med",
       NO_STR
       BGP_STR
       "Allow comparing MED from different neighbors\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	UNSET_FLAG(bgp->flags, BGP_FLAG_ALWAYS_COMPARE_MED);
	bgp_recalculate_all_bestpaths(bgp);

	return CMD_SUCCESS;
}


DEFUN(bgp_ebgp_requires_policy, bgp_ebgp_requires_policy_cmd,
      "bgp ebgp-requires-policy",
      BGP_STR
      "Require in and out policy for eBGP peers (RFC8212)\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	SET_FLAG(bgp->flags, BGP_FLAG_EBGP_REQUIRES_POLICY);
	return CMD_SUCCESS;
}

DEFUN(no_bgp_ebgp_requires_policy, no_bgp_ebgp_requires_policy_cmd,
      "no bgp ebgp-requires-policy",
      NO_STR
      BGP_STR
      "Require in and out policy for eBGP peers (RFC8212)\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	UNSET_FLAG(bgp->flags, BGP_FLAG_EBGP_REQUIRES_POLICY);
	return CMD_SUCCESS;
}

DEFPY(bgp_enforce_first_as,
      bgp_enforce_first_as_cmd,
      "[no] bgp enforce-first-as",
      NO_STR
      BGP_STR
      "Enforce the first AS for EBGP routes\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	if (no)
		UNSET_FLAG(bgp->flags, BGP_FLAG_ENFORCE_FIRST_AS);
	else
		SET_FLAG(bgp->flags, BGP_FLAG_ENFORCE_FIRST_AS);

	return CMD_SUCCESS;
}

DEFPY(bgp_lu_uses_explicit_null, bgp_lu_uses_explicit_null_cmd,
      "[no] bgp labeled-unicast <explicit-null|ipv4-explicit-null|ipv6-explicit-null>$value",
      NO_STR BGP_STR
      "BGP Labeled-unicast options\n"
      "Use explicit-null label values for all local prefixes\n"
      "Use the IPv4 explicit-null label value for IPv4 local prefixes\n"
      "Use the IPv6 explicit-null label value for IPv6 local prefixes\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	uint64_t label_mode;

	if (strmatch(value, "ipv4-explicit-null"))
		label_mode = BGP_FLAG_LU_IPV4_EXPLICIT_NULL;
	else if (strmatch(value, "ipv6-explicit-null"))
		label_mode = BGP_FLAG_LU_IPV6_EXPLICIT_NULL;
	else
		label_mode = BGP_FLAG_LU_IPV4_EXPLICIT_NULL |
			     BGP_FLAG_LU_IPV6_EXPLICIT_NULL;
	if (no)
		UNSET_FLAG(bgp->flags, label_mode);
	else
		SET_FLAG(bgp->flags, label_mode);
	return CMD_SUCCESS;
}

DEFUN(bgp_suppress_duplicates, bgp_suppress_duplicates_cmd,
      "bgp suppress-duplicates",
      BGP_STR
      "Suppress duplicate updates if the route actually not changed\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	SET_FLAG(bgp->flags, BGP_FLAG_SUPPRESS_DUPLICATES);
	return CMD_SUCCESS;
}

DEFUN(no_bgp_suppress_duplicates, no_bgp_suppress_duplicates_cmd,
      "no bgp suppress-duplicates",
      NO_STR
      BGP_STR
      "Suppress duplicate updates if the route actually not changed\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	UNSET_FLAG(bgp->flags, BGP_FLAG_SUPPRESS_DUPLICATES);
	return CMD_SUCCESS;
}

DEFUN(bgp_reject_as_sets, bgp_reject_as_sets_cmd,
      "bgp reject-as-sets",
      BGP_STR
      "Reject routes with AS_SET or AS_CONFED_SET flag\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	struct listnode *node, *nnode;
	struct peer *peer;

	bgp->reject_as_sets = true;

	/* Reset existing BGP sessions to reject routes
	 * with aspath containing AS_SET or AS_CONFED_SET.
	 */
	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
		peer->last_reset = PEER_DOWN_AS_SETS_REJECT;
		if (BGP_IS_VALID_STATE_FOR_NOTIF(peer->connection->status))
			bgp_notify_send(peer->connection, BGP_NOTIFY_CEASE,
					BGP_NOTIFY_CEASE_CONFIG_CHANGE);
	}

	return CMD_SUCCESS;
}

DEFUN(no_bgp_reject_as_sets, no_bgp_reject_as_sets_cmd,
      "no bgp reject-as-sets",
      NO_STR
      BGP_STR
      "Reject routes with AS_SET or AS_CONFED_SET flag\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	struct listnode *node, *nnode;
	struct peer *peer;

	bgp->reject_as_sets = false;

	/* Reset existing BGP sessions to reject routes
	 * with aspath containing AS_SET or AS_CONFED_SET.
	 */
	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
		peer->last_reset = PEER_DOWN_AS_SETS_REJECT;
		if (BGP_IS_VALID_STATE_FOR_NOTIF(peer->connection->status))
			bgp_notify_send(peer->connection, BGP_NOTIFY_CEASE,
					BGP_NOTIFY_CEASE_CONFIG_CHANGE);
	}

	return CMD_SUCCESS;
}

/* "bgp deterministic-med" configuration. */
DEFUN (bgp_deterministic_med,
       bgp_deterministic_med_cmd,
       "bgp deterministic-med",
       BGP_STR
       "Pick the best-MED path among paths advertised from the neighboring AS\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	if (!CHECK_FLAG(bgp->flags, BGP_FLAG_DETERMINISTIC_MED)) {
		SET_FLAG(bgp->flags, BGP_FLAG_DETERMINISTIC_MED);
		bgp_recalculate_all_bestpaths(bgp);
	}

	return CMD_SUCCESS;
}

DEFUN (no_bgp_deterministic_med,
       no_bgp_deterministic_med_cmd,
       "no bgp deterministic-med",
       NO_STR
       BGP_STR
       "Pick the best-MED path among paths advertised from the neighboring AS\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int bestpath_per_as_used;
	afi_t afi;
	safi_t safi;
	struct peer *peer;
	struct listnode *node, *nnode;

	if (CHECK_FLAG(bgp->flags, BGP_FLAG_DETERMINISTIC_MED)) {
		bestpath_per_as_used = 0;

		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
			FOREACH_AFI_SAFI (afi, safi)
				if (bgp_addpath_dmed_required(
					peer->addpath_type[afi][safi])) {
					bestpath_per_as_used = 1;
					break;
				}

			if (bestpath_per_as_used)
				break;
		}

		if (bestpath_per_as_used) {
			vty_out(vty,
				"bgp deterministic-med cannot be disabled while addpath-tx-bestpath-per-AS is in use\n");
			return CMD_WARNING_CONFIG_FAILED;
		} else {
			UNSET_FLAG(bgp->flags, BGP_FLAG_DETERMINISTIC_MED);
			bgp_recalculate_all_bestpaths(bgp);
		}
	}

	return CMD_SUCCESS;
}

static int bgp_inst_gr_config_vty(struct vty *vty, struct bgp *bgp, bool on,
				  bool disable)
{
	int ret = BGP_GR_FAILURE;

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

	VTY_BGP_GR_ROUTER_DETECT_AND_SEND_CAPABILITY_TO_ZEBRA(bgp, bgp->peer,
							      ret);
	return ret;
}

static int bgp_global_gr_config_vty(struct vty *vty, bool on, bool disable)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;
	bool vrf_cfg = false;
	int ret = BGP_GR_FAILURE;

	if (disable) {
		if ((on && CHECK_FLAG(bm->flags, BM_FLAG_GR_DISABLED)) ||
		    (!on && !CHECK_FLAG(bm->flags, BM_FLAG_GR_DISABLED)))
			return CMD_SUCCESS;
	} else {
		if ((on && CHECK_FLAG(bm->flags, BM_FLAG_GR_RESTARTER)) ||
		    (!on && !CHECK_FLAG(bm->flags, BM_FLAG_GR_RESTARTER)))
			return CMD_SUCCESS;
	}

	/* See if GR is set per-vrf and warn user to delete */
	if (!CHECK_FLAG(bm->flags, BM_FLAG_GR_CONFIGURED)) {
		for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
			enum global_mode gr_mode = bgp_global_gr_mode_get(bgp);

			if (gr_mode != GLOBAL_HELPER) {
				vty_out(vty,
					"%% graceful-restart configuration found in %s, mode %d\n",
					bgp->name_pretty, gr_mode);
				vrf_cfg = true;
			}
		}
	}

	if (vrf_cfg) {
		vty_out(vty,
			"%%Failed: global graceful-restart not permitted with per-vrf configuration\n");
		return CMD_WARNING;
	}

	/* Set flag globally */
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

	/* Initiate processing for all BGP instances. */
	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		ret = bgp_inst_gr_config_vty(vty, bgp, on, disable);
		if (ret != BGP_GR_SUCCESS)
			vty_out(vty,
				"%% Applying global graceful-restart %s config to vrf %s failed, error %d\n",
				(disable) ? "disable" : "",
				bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT
					? "Default"
					: bgp->name,
				ret);
	}

	vty_out(vty,
		"Graceful restart configuration changed, reset all peers to take effect\n");
	return bgp_vty_return(vty, ret);
}

/* "bgp graceful-restart mode" configuration. */
DEFUN (bgp_graceful_restart,
	bgp_graceful_restart_cmd,
	"bgp graceful-restart",
	BGP_STR
	GR_CMD
      )
{
	if (vty->node == CONFIG_NODE)
		return bgp_global_gr_config_vty(vty, true, false);

	int ret = BGP_GR_FAILURE;
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	ret = bgp_inst_gr_config_vty(vty, bgp, true, false);
	if (ret == BGP_GR_SUCCESS) {
		vty_out(vty,
			"Graceful restart configuration changed, reset all peers to take effect\n");
	}

	return bgp_vty_return(vty, ret);
}

DEFUN (no_bgp_graceful_restart,
	no_bgp_graceful_restart_cmd,
	"no bgp graceful-restart",
	NO_STR
	BGP_STR
	NO_GR_CMD
      )
{
	if (vty->node == CONFIG_NODE)
		return bgp_global_gr_config_vty(vty, false, false);

	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int ret = BGP_GR_FAILURE;

	ret = bgp_inst_gr_config_vty(vty, bgp, false, false);
	if (ret == BGP_GR_SUCCESS) {
		VTY_BGP_GR_ROUTER_DETECT_AND_SEND_CAPABILITY_TO_ZEBRA(bgp,
								      bgp->peer,
								      ret);
		vty_out(vty,
			"Graceful restart configuration changed, reset all peers to take effect\n");
	}

	return bgp_vty_return(vty, ret);
}

DEFUN (bgp_graceful_restart_stalepath_time,
	bgp_graceful_restart_stalepath_time_cmd,
	"bgp graceful-restart stalepath-time (1-4095)",
	BGP_STR
	"Graceful restart capability parameters\n"
	"Set the max time to hold onto restarting peer's stale paths\n"
	"Delay value (seconds)\n")
{
	int idx_number = 3;
	uint32_t stalepath;

	stalepath = strtoul(argv[idx_number]->arg, NULL, 10);
	if (vty->node == CONFIG_NODE) {
		struct listnode *node, *nnode;
		struct bgp *bgp;

		bm->stalepath_time = stalepath;
		for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp))
			bgp->stalepath_time = stalepath;
	} else {
		VTY_DECLVAR_CONTEXT(bgp, bgp);
		bgp->stalepath_time = stalepath;
	}
	return CMD_SUCCESS;
}

DEFUN (bgp_graceful_restart_restart_time,
	bgp_graceful_restart_restart_time_cmd,
	"bgp graceful-restart restart-time (0-4095)",
	BGP_STR
	"Graceful restart capability parameters\n"
	"Set the time to wait to delete stale routes before a BGP open message is received\n"
	"Delay value (seconds)\n")
{
	int idx_number = 3;
	uint32_t restart;
	struct listnode *node, *nnode;
	struct peer *peer;

	restart = strtoul(argv[idx_number]->arg, NULL, 10);

	if (vty->node == CONFIG_NODE) {
		struct bgp *bgp;

		bm->restart_time = restart;
		for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
			bgp->restart_time = restart;
			for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer))
				bgp_capability_send(peer, AFI_IP, SAFI_UNICAST,
						    CAPABILITY_CODE_RESTART,
						    CAPABILITY_ACTION_SET);
		}
	} else {
		VTY_DECLVAR_CONTEXT(bgp, bgp);
		bgp->restart_time = restart;
		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer))
			bgp_capability_send(peer, AFI_IP, SAFI_UNICAST,
					    CAPABILITY_CODE_RESTART,
					    CAPABILITY_ACTION_SET);
	}
	return CMD_SUCCESS;
}

DEFUN (bgp_graceful_restart_select_defer_time,
       bgp_graceful_restart_select_defer_time_cmd,
       "bgp graceful-restart select-defer-time (0-3600)",
       BGP_STR
       "Graceful restart capability parameters\n"
       "Set the time to defer the BGP route selection after restart\n"
       "Delay value (seconds, 0 - disable)\n")
{
	int idx_number = 3;
	uint32_t defer_time;

	defer_time = strtoul(argv[idx_number]->arg, NULL, 10);
	if (vty->node == CONFIG_NODE) {
		struct listnode *node, *nnode;
		struct bgp *bgp;

		bm->select_defer_time = defer_time;
		for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
			bgp->select_defer_time = defer_time;
			if (defer_time == 0)
				SET_FLAG(bgp->flags,
					 BGP_FLAG_SELECT_DEFER_DISABLE);
			else
				UNSET_FLAG(bgp->flags,
					   BGP_FLAG_SELECT_DEFER_DISABLE);
		}
	} else {
		VTY_DECLVAR_CONTEXT(bgp, bgp);
		bgp->select_defer_time = defer_time;
		if (defer_time == 0)
			SET_FLAG(bgp->flags, BGP_FLAG_SELECT_DEFER_DISABLE);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_SELECT_DEFER_DISABLE);
	}

	return CMD_SUCCESS;
}

DEFUN (no_bgp_graceful_restart_stalepath_time,
	no_bgp_graceful_restart_stalepath_time_cmd,
	"no bgp graceful-restart stalepath-time [(1-4095)]",
	NO_STR
	BGP_STR
	"Graceful restart capability parameters\n"
	"Set the max time to hold onto restarting peer's stale paths\n"
	"Delay value (seconds)\n")
{
	if (vty->node == CONFIG_NODE) {
		struct listnode *node, *nnode;
		struct bgp *bgp;

		bm->stalepath_time = BGP_DEFAULT_STALEPATH_TIME;
		for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp))
			bgp->stalepath_time = BGP_DEFAULT_STALEPATH_TIME;
	} else {
		VTY_DECLVAR_CONTEXT(bgp, bgp);
		bgp->stalepath_time = BGP_DEFAULT_STALEPATH_TIME;
	}
	return CMD_SUCCESS;
}

DEFUN (no_bgp_graceful_restart_restart_time,
	no_bgp_graceful_restart_restart_time_cmd,
	"no bgp graceful-restart restart-time [(0-4095)]",
	NO_STR
	BGP_STR
	"Graceful restart capability parameters\n"
	"Set the time to wait to delete stale routes before a BGP open message is received\n"
	"Delay value (seconds)\n")
{
	struct listnode *node, *nnode;
	struct peer *peer;

	if (vty->node == CONFIG_NODE) {
		struct bgp *bgp;

		bm->restart_time = BGP_DEFAULT_RESTART_TIME;
		for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
			bgp->restart_time = BGP_DEFAULT_RESTART_TIME;

			for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer))
				bgp_capability_send(peer, AFI_IP, SAFI_UNICAST,
						    CAPABILITY_CODE_RESTART,
						    CAPABILITY_ACTION_UNSET);
		}
	} else {
		VTY_DECLVAR_CONTEXT(bgp, bgp);
		bgp->restart_time = BGP_DEFAULT_RESTART_TIME;

		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer))
			bgp_capability_send(peer, AFI_IP, SAFI_UNICAST,
					    CAPABILITY_CODE_RESTART,
					    CAPABILITY_ACTION_UNSET);
	}
	return CMD_SUCCESS;
}

DEFUN (no_bgp_graceful_restart_select_defer_time,
       no_bgp_graceful_restart_select_defer_time_cmd,
       "no bgp graceful-restart select-defer-time [(0-3600)]",
       NO_STR
       BGP_STR
       "Graceful restart capability parameters\n"
       "Set the time to defer the BGP route selection after restart\n"
       "Delay value (seconds)\n")
{
	if (vty->node == CONFIG_NODE) {
		struct listnode *node, *nnode;
		struct bgp *bgp;

		bm->select_defer_time = BGP_DEFAULT_SELECT_DEFERRAL_TIME;
		for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
			bgp->select_defer_time =
				BGP_DEFAULT_SELECT_DEFERRAL_TIME;
			UNSET_FLAG(bgp->flags, BGP_FLAG_SELECT_DEFER_DISABLE);
		}
	} else {
		VTY_DECLVAR_CONTEXT(bgp, bgp);
		bgp->select_defer_time = BGP_DEFAULT_SELECT_DEFERRAL_TIME;
		UNSET_FLAG(bgp->flags, BGP_FLAG_SELECT_DEFER_DISABLE);
	}

	return CMD_SUCCESS;
}

DEFUN (bgp_graceful_restart_preserve_fw,
	bgp_graceful_restart_preserve_fw_cmd,
	"bgp graceful-restart preserve-fw-state",
	BGP_STR
	"Graceful restart capability parameters\n"
	"Sets F-bit indication that fib is preserved while doing Graceful Restart\n")
{
	if (vty->node == CONFIG_NODE) {
		struct listnode *node, *nnode;
		struct bgp *bgp;

		SET_FLAG(bm->flags, BM_FLAG_GR_PRESERVE_FWD);
		for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp))
			SET_FLAG(bgp->flags, BGP_FLAG_GR_PRESERVE_FWD);
	} else {
		VTY_DECLVAR_CONTEXT(bgp, bgp);
		SET_FLAG(bgp->flags, BGP_FLAG_GR_PRESERVE_FWD);
	}
	return CMD_SUCCESS;
}

DEFUN (no_bgp_graceful_restart_preserve_fw,
	no_bgp_graceful_restart_preserve_fw_cmd,
	"no bgp graceful-restart preserve-fw-state",
	NO_STR
	BGP_STR
	"Graceful restart capability parameters\n"
	"Unsets F-bit indication that fib is preserved while doing Graceful Restart\n")
{
	if (vty->node == CONFIG_NODE) {
		struct listnode *node, *nnode;
		struct bgp *bgp;

		UNSET_FLAG(bm->flags, BM_FLAG_GR_PRESERVE_FWD);
		for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp))
			UNSET_FLAG(bgp->flags, BGP_FLAG_GR_PRESERVE_FWD);
	} else {
		VTY_DECLVAR_CONTEXT(bgp, bgp);
		UNSET_FLAG(bgp->flags, BGP_FLAG_GR_PRESERVE_FWD);
	}
	return CMD_SUCCESS;
}

DEFPY (bgp_graceful_restart_notification,
	bgp_graceful_restart_notification_cmd,
	"[no$no] bgp graceful-restart notification",
	NO_STR
	BGP_STR
	"Graceful restart capability parameters\n"
	"Indicate Graceful Restart support for BGP NOTIFICATION messages\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	struct listnode *node, *nnode;
	struct peer *peer;

	if (no)
		UNSET_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_NOTIFICATION);
	else
		SET_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_NOTIFICATION);

	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer))
		bgp_capability_send(peer, AFI_IP, SAFI_UNICAST,
				    CAPABILITY_CODE_RESTART,
				    CAPABILITY_ACTION_SET);

	return CMD_SUCCESS;
}

DEFPY (bgp_administrative_reset,
	bgp_administrative_reset_cmd,
	"[no$no] bgp hard-administrative-reset",
	NO_STR
	BGP_STR
	"Send Hard Reset CEASE Notification for 'Administrative Reset'\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	if (no)
		UNSET_FLAG(bgp->flags, BGP_FLAG_HARD_ADMIN_RESET);
	else
		SET_FLAG(bgp->flags, BGP_FLAG_HARD_ADMIN_RESET);

	return CMD_SUCCESS;
}

DEFUN (bgp_graceful_restart_disable,
	bgp_graceful_restart_disable_cmd,
	"bgp graceful-restart-disable",
	BGP_STR
	GR_DISABLE)
{
	if (vty->node == CONFIG_NODE)
		return bgp_global_gr_config_vty(vty, true, true);

	int ret = BGP_GR_FAILURE;
	struct listnode *node, *nnode;
	struct peer *peer;

	VTY_DECLVAR_CONTEXT(bgp, bgp);

	ret = bgp_inst_gr_config_vty(vty, bgp, true, true);
	if (ret == BGP_GR_SUCCESS) {
		vty_out(vty,
			"Graceful restart configuration changed, reset all peers to take effect\n");

		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
			bgp_capability_send(peer, AFI_IP, SAFI_UNICAST,
					    CAPABILITY_CODE_RESTART,
					    CAPABILITY_ACTION_UNSET);
			bgp_capability_send(peer, AFI_IP, SAFI_UNICAST,
					    CAPABILITY_CODE_LLGR,
					    CAPABILITY_ACTION_UNSET);
		}
	}

	return bgp_vty_return(vty, ret);
}

DEFUN (no_bgp_graceful_restart_disable,
	no_bgp_graceful_restart_disable_cmd,
	"no bgp graceful-restart-disable",
	NO_STR
	BGP_STR
	NO_GR_DISABLE
      )
{
	if (vty->node == CONFIG_NODE)
		return bgp_global_gr_config_vty(vty, false, true);

	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int ret = BGP_GR_FAILURE;

	ret = bgp_inst_gr_config_vty(vty, bgp, false, true);
	if (ret == BGP_GR_SUCCESS) {
		vty_out(vty,
			"Graceful restart configuration changed, reset all peers to take effect\n");
	}

	return bgp_vty_return(vty, ret);
}

DEFUN (bgp_neighbor_graceful_restart_set,
	bgp_neighbor_graceful_restart_set_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD> graceful-restart",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	GR_NEIGHBOR_CMD
      )
{
	int idx_peer = 1;
	struct peer *peer;
	int result = BGP_GR_FAILURE, ret = BGP_GR_SUCCESS;

	VTY_BGP_GR_DEFINE_LOOP_VARIABLE;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;
	if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		vty_out(vty,
			"Per peer-group graceful-restart configuration is not yet supported\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	result = bgp_neighbor_graceful_restart(peer, PEER_GR_CMD);
	if (result == BGP_GR_SUCCESS) {
		VTY_BGP_GR_ROUTER_DETECT(bgp, peer, peer->bgp->peer);
		VTY_SEND_BGP_GR_CAPABILITY_TO_ZEBRA(peer->bgp, ret);
		vty_out(vty,
			"Graceful restart configuration changed, reset this peer to take effect\n");
	}

	return bgp_vty_return(vty, ret);
}

DEFUN (no_bgp_neighbor_graceful_restart,
	no_bgp_neighbor_graceful_restart_set_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD> graceful-restart",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	NO_GR_NEIGHBOR_CMD
      )
{
	int idx_peer = 2;
	int result = BGP_GR_FAILURE, ret = BGP_GR_SUCCESS;
	struct peer *peer;

	VTY_BGP_GR_DEFINE_LOOP_VARIABLE;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;
	if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		vty_out(vty,
			"Per peer-group graceful-restart configuration is not yet supported\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	result = bgp_neighbor_graceful_restart(peer, NO_PEER_GR_CMD);
	if (ret == BGP_GR_SUCCESS) {
		VTY_BGP_GR_ROUTER_DETECT(bgp, peer, peer->bgp->peer);
		VTY_SEND_BGP_GR_CAPABILITY_TO_ZEBRA(peer->bgp, ret);
		vty_out(vty,
			"Graceful restart configuration changed, reset this peer to take effect\n");
	}

	return bgp_vty_return(vty, result);
}

DEFUN (bgp_neighbor_graceful_restart_helper_set,
	bgp_neighbor_graceful_restart_helper_set_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD> graceful-restart-helper",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	GR_NEIGHBOR_HELPER_CMD
      )
{
	int idx_peer = 1;
	struct peer *peer;
	int ret = BGP_GR_FAILURE;

	VTY_BGP_GR_DEFINE_LOOP_VARIABLE;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;
	if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		vty_out(vty,
			"Per peer-group graceful-restart configuration is not yet supported\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ret = bgp_neighbor_graceful_restart(peer, PEER_HELPER_CMD);
	if (ret == BGP_GR_SUCCESS) {
		VTY_BGP_GR_ROUTER_DETECT(bgp, peer, peer->bgp->peer);
		VTY_SEND_BGP_GR_CAPABILITY_TO_ZEBRA(peer->bgp, ret);
		vty_out(vty,
			"Graceful restart configuration changed, reset this peer to take effect\n");
	}

	return bgp_vty_return(vty, ret);
}

DEFUN (no_bgp_neighbor_graceful_restart_helper,
	no_bgp_neighbor_graceful_restart_helper_set_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD> graceful-restart-helper",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	NO_GR_NEIGHBOR_HELPER_CMD
      )
{
	int idx_peer = 2;
	int ret = BGP_GR_FAILURE;
	struct peer *peer;

	VTY_BGP_GR_DEFINE_LOOP_VARIABLE;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;
	if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		vty_out(vty,
			"Per peer-group graceful-restart configuration is not yet supported\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ret = bgp_neighbor_graceful_restart(peer, NO_PEER_HELPER_CMD);
	if (ret == BGP_GR_SUCCESS) {
		VTY_BGP_GR_ROUTER_DETECT(bgp, peer, peer->bgp->peer);
		VTY_SEND_BGP_GR_CAPABILITY_TO_ZEBRA(peer->bgp, ret);
		vty_out(vty,
			"Graceful restart configuration changed, reset this peer to take effect\n");
	}

	return bgp_vty_return(vty, ret);
}

DEFUN (bgp_neighbor_graceful_restart_disable_set,
	bgp_neighbor_graceful_restart_disable_set_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD> graceful-restart-disable",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	GR_NEIGHBOR_DISABLE_CMD
      )
{
	int idx_peer = 1;
	struct peer *peer;
	int ret = BGP_GR_FAILURE;

	VTY_BGP_GR_DEFINE_LOOP_VARIABLE;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;
	if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		vty_out(vty,
			"Per peer-group graceful-restart configuration is not yet supported\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ret = bgp_neighbor_graceful_restart(peer, PEER_DISABLE_CMD);
	if (ret == BGP_GR_SUCCESS) {
		if (peer->bgp->t_startup || bgp_in_graceful_restart())
			bgp_peer_gr_flags_update(peer);

		VTY_BGP_GR_ROUTER_DETECT(bgp, peer, peer->bgp->peer);
		VTY_SEND_BGP_GR_CAPABILITY_TO_ZEBRA(peer->bgp, ret);
	}

	return bgp_vty_return(vty, ret);
}

DEFUN (no_bgp_neighbor_graceful_restart_disable,
	no_bgp_neighbor_graceful_restart_disable_set_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD> graceful-restart-disable",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	NO_GR_NEIGHBOR_DISABLE_CMD
      )
{
	int idx_peer = 2;
	int ret = BGP_GR_FAILURE;
	struct peer *peer;

	VTY_BGP_GR_DEFINE_LOOP_VARIABLE;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;
	if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		vty_out(vty,
			"Per peer-group graceful-restart configuration is not yet supported\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ret = bgp_neighbor_graceful_restart(peer, NO_PEER_DISABLE_CMD);
	if (ret == BGP_GR_SUCCESS) {
		VTY_BGP_GR_ROUTER_DETECT(bgp, peer, peer->bgp->peer);
		VTY_SEND_BGP_GR_CAPABILITY_TO_ZEBRA(peer->bgp, ret);
	}

	return bgp_vty_return(vty, ret);
}

DEFPY (neighbor_graceful_shutdown,
       neighbor_graceful_shutdown_cmd,
       "[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor graceful-shutdown",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Graceful shutdown\n")
{
	afi_t afi;
	safi_t safi;
	struct peer *peer;
	int ret;

	VTY_DECLVAR_CONTEXT(bgp, bgp);

	peer = peer_and_group_lookup_vty(vty, neighbor);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	if (no)
		ret = peer_flag_unset_vty(vty, neighbor,
					  PEER_FLAG_GRACEFUL_SHUTDOWN);
	else
		ret = peer_flag_set_vty(vty, neighbor,
					PEER_FLAG_GRACEFUL_SHUTDOWN);

	FOREACH_AFI_SAFI (afi, safi) {
		if (!peer->afc[afi][safi])
			continue;

		bgp_clear(vty, bgp, afi, safi, clear_peer, BGP_CLEAR_SOFT_IN,
			  neighbor);
	}

	return ret;
}

DEFUN_HIDDEN (bgp_graceful_restart_disable_eor,
              bgp_graceful_restart_disable_eor_cmd,
              "bgp graceful-restart disable-eor",
              BGP_STR
              "Graceful restart configuration parameters\n"
              "Disable EOR Check\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	SET_FLAG(bgp->flags, BGP_FLAG_GR_DISABLE_EOR);

	return CMD_SUCCESS;
}

DEFUN_HIDDEN (no_bgp_graceful_restart_disable_eor,
              no_bgp_graceful_restart_disable_eor_cmd,
              "no bgp graceful-restart disable-eor",
              NO_STR
              BGP_STR
              "Graceful restart configuration parameters\n"
              "Disable EOR Check\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	UNSET_FLAG(bgp->flags, BGP_FLAG_GR_DISABLE_EOR);

	return CMD_SUCCESS;
}

DEFUN (bgp_graceful_restart_rib_stale_time,
       bgp_graceful_restart_rib_stale_time_cmd,
       "bgp graceful-restart rib-stale-time (1-3600)",
       BGP_STR
       "Graceful restart configuration parameters\n"
       "Specify the stale route removal timer in rib\n"
       "Delay value (seconds)\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_number = 3;
	uint32_t stale_time;

	stale_time = strtoul(argv[idx_number]->arg, NULL, 10);
	bgp->rib_stale_time = stale_time;
	/* Send the stale timer update message to RIB */
	if (bgp_zebra_stale_timer_update(bgp))
		return CMD_WARNING;

	return CMD_SUCCESS;
}

DEFUN (no_bgp_graceful_restart_rib_stale_time,
       no_bgp_graceful_restart_rib_stale_time_cmd,
       "no bgp graceful-restart rib-stale-time [(1-3600)]",
       NO_STR
       BGP_STR
       "Graceful restart configuration parameters\n"
       "Specify the stale route removal timer in rib\n"
       "Delay value (seconds)\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	bgp->rib_stale_time = BGP_DEFAULT_RIB_STALE_TIME;
	/* Send the stale timer update message to RIB */
	if (bgp_zebra_stale_timer_update(bgp))
		return CMD_WARNING;

	return CMD_SUCCESS;
}

DEFUN(bgp_llgr_stalepath_time, bgp_llgr_stalepath_time_cmd,
      "bgp long-lived-graceful-restart stale-time (1-16777215)",
      BGP_STR
      "Enable Long-lived Graceful Restart\n"
      "Specifies maximum time to wait before purging long-lived stale routes\n"
      "Stale time value (seconds)\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	uint32_t llgr_stale_time;
	struct listnode *node, *nnode;
	struct peer *peer;

	llgr_stale_time = strtoul(argv[3]->arg, NULL, 10);
	bgp->llgr_stale_time = llgr_stale_time;

	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer))
		bgp_capability_send(peer, AFI_IP, SAFI_UNICAST,
				    CAPABILITY_CODE_LLGR, CAPABILITY_ACTION_SET);

	return CMD_SUCCESS;
}

DEFUN(no_bgp_llgr_stalepath_time, no_bgp_llgr_stalepath_time_cmd,
      "no bgp long-lived-graceful-restart stale-time [(1-16777215)]",
      NO_STR BGP_STR
      "Enable Long-lived Graceful Restart\n"
      "Specifies maximum time to wait before purging long-lived stale routes\n"
      "Stale time value (seconds)\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	struct listnode *node, *nnode;
	struct peer *peer;

	bgp->llgr_stale_time = BGP_DEFAULT_LLGR_STALE_TIME;

	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer))
		bgp_capability_send(peer, AFI_IP, SAFI_UNICAST,
				    CAPABILITY_CODE_LLGR,
				    CAPABILITY_ACTION_UNSET);

	return CMD_SUCCESS;
}

static inline void bgp_initiate_graceful_shut_unshut(struct vty *vty,
						     struct bgp *bgp)
{
	bgp_static_redo_import_check(bgp);
	bgp_redistribute_redo(bgp);
	bgp_clear_star_soft_out(vty, bgp->name);
	bgp_clear_star_soft_in(vty, bgp->name);
}

static int bgp_global_graceful_shutdown_config_vty(struct vty *vty)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;
	bool vrf_cfg = false;

	if (CHECK_FLAG(bm->flags, BM_FLAG_GRACEFUL_SHUTDOWN))
		return CMD_SUCCESS;

	/* See if graceful-shutdown is set per-vrf and warn user to delete */
	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		if (CHECK_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_SHUTDOWN)) {
			vty_out(vty,
				"%% graceful-shutdown configuration found in vrf %s\n",
				bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT ?
					VRF_DEFAULT_NAME : bgp->name);
			vrf_cfg = true;
		}
	}

	if (vrf_cfg) {
		vty_out(vty,
			"%%Failed: global graceful-shutdown not permitted\n");
		return CMD_WARNING;
	}

	/* Set flag globally */
	SET_FLAG(bm->flags, BM_FLAG_GRACEFUL_SHUTDOWN);

	/* Initiate processing for all BGP instances. */
	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp))
		bgp_initiate_graceful_shut_unshut(vty, bgp);

	return CMD_SUCCESS;
}

static int bgp_global_graceful_shutdown_deconfig_vty(struct vty *vty)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;

	if (!CHECK_FLAG(bm->flags, BM_FLAG_GRACEFUL_SHUTDOWN))
		return CMD_SUCCESS;

	/* Unset flag globally */
	UNSET_FLAG(bm->flags, BM_FLAG_GRACEFUL_SHUTDOWN);

	/* Initiate processing for all BGP instances. */
	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp))
		bgp_initiate_graceful_shut_unshut(vty, bgp);

	return CMD_SUCCESS;
}

/* "bgp graceful-shutdown" configuration */
DEFUN (bgp_graceful_shutdown,
       bgp_graceful_shutdown_cmd,
       "bgp graceful-shutdown",
       BGP_STR
       "Graceful shutdown parameters\n")
{
	if (vty->node == CONFIG_NODE)
		return bgp_global_graceful_shutdown_config_vty(vty);

	VTY_DECLVAR_CONTEXT(bgp, bgp);

	/* if configured globally, per-instance config is not allowed */
	if (CHECK_FLAG(bm->flags, BM_FLAG_GRACEFUL_SHUTDOWN)) {
		vty_out(vty,
			"%%Failed: per-vrf graceful-shutdown config not permitted with global graceful-shutdown\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (!CHECK_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_SHUTDOWN)) {
		SET_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_SHUTDOWN);
		bgp_initiate_graceful_shut_unshut(vty, bgp);
	}

	return CMD_SUCCESS;
}

DEFUN (no_bgp_graceful_shutdown,
       no_bgp_graceful_shutdown_cmd,
       "no bgp graceful-shutdown",
       NO_STR
       BGP_STR
       "Graceful shutdown parameters\n")
{
	if (vty->node == CONFIG_NODE)
		return bgp_global_graceful_shutdown_deconfig_vty(vty);

	VTY_DECLVAR_CONTEXT(bgp, bgp);

	/* If configured globally, cannot remove from one bgp instance */
	if (CHECK_FLAG(bm->flags, BM_FLAG_GRACEFUL_SHUTDOWN)) {
		vty_out(vty,
			"%%Failed: bgp graceful-shutdown configured globally. Delete per-vrf not permitted\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (CHECK_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_SHUTDOWN)) {
		UNSET_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_SHUTDOWN);
		bgp_initiate_graceful_shut_unshut(vty, bgp);
	}

	return CMD_SUCCESS;
}

/* "bgp fast-external-failover" configuration. */
DEFUN (bgp_fast_external_failover,
       bgp_fast_external_failover_cmd,
       "bgp fast-external-failover",
       BGP_STR
       "Immediately reset session if a link to a directly connected external peer goes down\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	UNSET_FLAG(bgp->flags, BGP_FLAG_NO_FAST_EXT_FAILOVER);
	return CMD_SUCCESS;
}

DEFUN (no_bgp_fast_external_failover,
       no_bgp_fast_external_failover_cmd,
       "no bgp fast-external-failover",
       NO_STR
       BGP_STR
       "Immediately reset session if a link to a directly connected external peer goes down\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	SET_FLAG(bgp->flags, BGP_FLAG_NO_FAST_EXT_FAILOVER);
	return CMD_SUCCESS;
}

DEFPY (bgp_bestpath_aigp,
       bgp_bestpath_aigp_cmd,
       "[no$no] bgp bestpath aigp",
       NO_STR
       BGP_STR
       "Change the default bestpath selection\n"
       "Evaluate the AIGP attribute during the best path selection process\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	if (no)
		UNSET_FLAG(bgp->flags, BGP_FLAG_COMPARE_AIGP);
	else
		SET_FLAG(bgp->flags, BGP_FLAG_COMPARE_AIGP);

	bgp_recalculate_all_bestpaths(bgp);

	return CMD_SUCCESS;
}

/* "bgp bestpath compare-routerid" configuration.  */
DEFUN (bgp_bestpath_compare_router_id,
       bgp_bestpath_compare_router_id_cmd,
       "bgp bestpath compare-routerid",
       BGP_STR
       "Change the default bestpath selection\n"
       "Compare router-id for identical EBGP paths\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	SET_FLAG(bgp->flags, BGP_FLAG_COMPARE_ROUTER_ID);
	bgp_recalculate_all_bestpaths(bgp);

	return CMD_SUCCESS;
}

DEFUN (no_bgp_bestpath_compare_router_id,
       no_bgp_bestpath_compare_router_id_cmd,
       "no bgp bestpath compare-routerid",
       NO_STR
       BGP_STR
       "Change the default bestpath selection\n"
       "Compare router-id for identical EBGP paths\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	UNSET_FLAG(bgp->flags, BGP_FLAG_COMPARE_ROUTER_ID);
	bgp_recalculate_all_bestpaths(bgp);

	return CMD_SUCCESS;
}

/* "bgp bestpath as-path ignore" configuration.  */
DEFUN (bgp_bestpath_aspath_ignore,
       bgp_bestpath_aspath_ignore_cmd,
       "bgp bestpath as-path ignore",
       BGP_STR
       "Change the default bestpath selection\n"
       "AS-path attribute\n"
       "Ignore as-path length in selecting a route\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	SET_FLAG(bgp->flags, BGP_FLAG_ASPATH_IGNORE);
	bgp_recalculate_all_bestpaths(bgp);

	return CMD_SUCCESS;
}

DEFUN (no_bgp_bestpath_aspath_ignore,
       no_bgp_bestpath_aspath_ignore_cmd,
       "no bgp bestpath as-path ignore",
       NO_STR
       BGP_STR
       "Change the default bestpath selection\n"
       "AS-path attribute\n"
       "Ignore as-path length in selecting a route\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	UNSET_FLAG(bgp->flags, BGP_FLAG_ASPATH_IGNORE);
	bgp_recalculate_all_bestpaths(bgp);

	return CMD_SUCCESS;
}

/* "bgp bestpath as-path confed" configuration.  */
DEFUN (bgp_bestpath_aspath_confed,
       bgp_bestpath_aspath_confed_cmd,
       "bgp bestpath as-path confed",
       BGP_STR
       "Change the default bestpath selection\n"
       "AS-path attribute\n"
       "Compare path lengths including confederation sets & sequences in selecting a route\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	SET_FLAG(bgp->flags, BGP_FLAG_ASPATH_CONFED);
	bgp_recalculate_all_bestpaths(bgp);

	return CMD_SUCCESS;
}

DEFUN (no_bgp_bestpath_aspath_confed,
       no_bgp_bestpath_aspath_confed_cmd,
       "no bgp bestpath as-path confed",
       NO_STR
       BGP_STR
       "Change the default bestpath selection\n"
       "AS-path attribute\n"
       "Compare path lengths including confederation sets & sequences in selecting a route\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	UNSET_FLAG(bgp->flags, BGP_FLAG_ASPATH_CONFED);
	bgp_recalculate_all_bestpaths(bgp);

	return CMD_SUCCESS;
}

/* "bgp bestpath as-path multipath-relax" configuration.  */
DEFUN (bgp_bestpath_aspath_multipath_relax,
       bgp_bestpath_aspath_multipath_relax_cmd,
       "bgp bestpath as-path multipath-relax [<as-set|no-as-set>]",
       BGP_STR
       "Change the default bestpath selection\n"
       "AS-path attribute\n"
       "Allow load sharing across routes that have different AS paths (but same length)\n"
       "Generate an AS_SET\n"
       "Do not generate an AS_SET\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx = 0;
	SET_FLAG(bgp->flags, BGP_FLAG_ASPATH_MULTIPATH_RELAX);

	/* no-as-set is now the default behavior so we can silently
	 * ignore it */
	if (argv_find(argv, argc, "as-set", &idx))
		SET_FLAG(bgp->flags, BGP_FLAG_MULTIPATH_RELAX_AS_SET);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_MULTIPATH_RELAX_AS_SET);

	bgp_recalculate_all_bestpaths(bgp);

	return CMD_SUCCESS;
}

DEFUN (no_bgp_bestpath_aspath_multipath_relax,
       no_bgp_bestpath_aspath_multipath_relax_cmd,
       "no bgp bestpath as-path multipath-relax [<as-set|no-as-set>]",
       NO_STR
       BGP_STR
       "Change the default bestpath selection\n"
       "AS-path attribute\n"
       "Allow load sharing across routes that have different AS paths (but same length)\n"
       "Generate an AS_SET\n"
       "Do not generate an AS_SET\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	UNSET_FLAG(bgp->flags, BGP_FLAG_ASPATH_MULTIPATH_RELAX);
	UNSET_FLAG(bgp->flags, BGP_FLAG_MULTIPATH_RELAX_AS_SET);
	bgp_recalculate_all_bestpaths(bgp);

	return CMD_SUCCESS;
}

/* "bgp bestpath peer-type multipath-relax" configuration. */
DEFUN(bgp_bestpath_peer_type_multipath_relax,
      bgp_bestpath_peer_type_multipath_relax_cmd,
      "bgp bestpath peer-type multipath-relax",
      BGP_STR
      "Change the default bestpath selection\n"
      "Peer type\n"
      "Allow load sharing across routes learned from different peer types\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	SET_FLAG(bgp->flags, BGP_FLAG_PEERTYPE_MULTIPATH_RELAX);
	bgp_recalculate_all_bestpaths(bgp);

	return CMD_SUCCESS;
}

DEFUN(no_bgp_bestpath_peer_type_multipath_relax,
      no_bgp_bestpath_peer_type_multipath_relax_cmd,
      "no bgp bestpath peer-type multipath-relax",
      NO_STR BGP_STR
      "Change the default bestpath selection\n"
      "Peer type\n"
      "Allow load sharing across routes learned from different peer types\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	UNSET_FLAG(bgp->flags, BGP_FLAG_PEERTYPE_MULTIPATH_RELAX);
	bgp_recalculate_all_bestpaths(bgp);

	return CMD_SUCCESS;
}

/* "bgp log-neighbor-changes" configuration.  */
DEFUN (bgp_log_neighbor_changes,
       bgp_log_neighbor_changes_cmd,
       "bgp log-neighbor-changes",
       BGP_STR
       "Log neighbor up/down and reset reason\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	SET_FLAG(bgp->flags, BGP_FLAG_LOG_NEIGHBOR_CHANGES);
	return CMD_SUCCESS;
}

DEFUN (no_bgp_log_neighbor_changes,
       no_bgp_log_neighbor_changes_cmd,
       "no bgp log-neighbor-changes",
       NO_STR
       BGP_STR
       "Log neighbor up/down and reset reason\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	UNSET_FLAG(bgp->flags, BGP_FLAG_LOG_NEIGHBOR_CHANGES);
	return CMD_SUCCESS;
}

/* "bgp bestpath med" configuration. */
DEFUN (bgp_bestpath_med,
       bgp_bestpath_med_cmd,
       "bgp bestpath med <confed [missing-as-worst]|missing-as-worst [confed]>",
       BGP_STR
       "Change the default bestpath selection\n"
       "MED attribute\n"
       "Compare MED among confederation paths\n"
       "Treat missing MED as the least preferred one\n"
       "Treat missing MED as the least preferred one\n"
       "Compare MED among confederation paths\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	int idx = 0;
	if (argv_find(argv, argc, "confed", &idx))
		SET_FLAG(bgp->flags, BGP_FLAG_MED_CONFED);
	idx = 0;
	if (argv_find(argv, argc, "missing-as-worst", &idx))
		SET_FLAG(bgp->flags, BGP_FLAG_MED_MISSING_AS_WORST);

	bgp_recalculate_all_bestpaths(bgp);

	return CMD_SUCCESS;
}

DEFUN (no_bgp_bestpath_med,
       no_bgp_bestpath_med_cmd,
       "no bgp bestpath med <confed [missing-as-worst]|missing-as-worst [confed]>",
       NO_STR
       BGP_STR
       "Change the default bestpath selection\n"
       "MED attribute\n"
       "Compare MED among confederation paths\n"
       "Treat missing MED as the least preferred one\n"
       "Treat missing MED as the least preferred one\n"
       "Compare MED among confederation paths\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	int idx = 0;
	if (argv_find(argv, argc, "confed", &idx))
		UNSET_FLAG(bgp->flags, BGP_FLAG_MED_CONFED);
	idx = 0;
	if (argv_find(argv, argc, "missing-as-worst", &idx))
		UNSET_FLAG(bgp->flags, BGP_FLAG_MED_MISSING_AS_WORST);

	bgp_recalculate_all_bestpaths(bgp);

	return CMD_SUCCESS;
}

/* "bgp bestpath bandwidth" configuration. */
DEFPY (bgp_bestpath_bw,
       bgp_bestpath_bw_cmd,
       "bgp bestpath bandwidth <ignore|skip-missing|default-weight-for-missing>$bw_cfg",
       BGP_STR
       "Change the default bestpath selection\n"
       "Link Bandwidth attribute\n"
       "Ignore link bandwidth (i.e., do regular ECMP, not weighted)\n"
       "Ignore paths without link bandwidth for ECMP (if other paths have it)\n"
       "Assign a low default weight (value 1) to paths not having link bandwidth\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	afi_t afi;
	safi_t safi;

	if (!bw_cfg) {
		vty_out(vty, "%% Bandwidth configuration must be specified\n");
		return CMD_ERR_INCOMPLETE;
	}
	if (!strcmp(bw_cfg, "ignore"))
		bgp->lb_handling = BGP_LINK_BW_IGNORE_BW;
	else if (!strcmp(bw_cfg, "skip-missing"))
		bgp->lb_handling = BGP_LINK_BW_SKIP_MISSING;
	else if (!strcmp(bw_cfg, "default-weight-for-missing"))
		bgp->lb_handling = BGP_LINK_BW_DEFWT_4_MISSING;
	else
		return CMD_ERR_NO_MATCH;

	/* This config is used in route install, so redo that. */
	FOREACH_AFI_SAFI (afi, safi) {
		if (!bgp_fibupd_safi(safi))
			continue;
		bgp_zebra_announce_table(bgp, afi, safi);
	}

	return CMD_SUCCESS;
}

DEFPY (no_bgp_bestpath_bw,
       no_bgp_bestpath_bw_cmd,
       "no bgp bestpath bandwidth [<ignore|skip-missing|default-weight-for-missing>$bw_cfg]",
       NO_STR
       BGP_STR
       "Change the default bestpath selection\n"
       "Link Bandwidth attribute\n"
       "Ignore link bandwidth (i.e., do regular ECMP, not weighted)\n"
       "Ignore paths without link bandwidth for ECMP (if other paths have it)\n"
       "Assign a low default weight (value 1) to paths not having link bandwidth\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	afi_t afi;
	safi_t safi;

	bgp->lb_handling = BGP_LINK_BW_ECMP;

	/* This config is used in route install, so redo that. */
	FOREACH_AFI_SAFI (afi, safi) {
		if (!bgp_fibupd_safi(safi))
			continue;
		bgp_zebra_announce_table(bgp, afi, safi);
	}
	return CMD_SUCCESS;
}

DEFPY(bgp_default_afi_safi, bgp_default_afi_safi_cmd,
      "[no] bgp default <ipv4-unicast|"
      "ipv4-multicast|"
      "ipv4-vpn|"
      "ipv4-labeled-unicast|"
      "ipv4-flowspec|"
      "ipv6-unicast|"
      "ipv6-multicast|"
      "ipv6-vpn|"
      "ipv6-labeled-unicast|"
      "ipv6-flowspec|"
      "l2vpn-evpn>$afi_safi",
      NO_STR
      BGP_STR
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
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	char afi_safi_str[strlen(afi_safi) + 1];
	char *afi_safi_str_tok;

	strlcpy(afi_safi_str, afi_safi, sizeof(afi_safi_str));
	char *afi_str = strtok_r(afi_safi_str, "-", &afi_safi_str_tok);
	char *safi_str = strtok_r(NULL, "-", &afi_safi_str_tok);
	afi_t afi = bgp_vty_afi_from_str(afi_str);
	safi_t safi;

	/*
	 * Impossible situation but making coverity happy
	 */
	assert(afi != AFI_MAX);

	if (strmatch(safi_str, "labeled"))
		safi = bgp_vty_safi_from_str("labeled-unicast");
	else
		safi = bgp_vty_safi_from_str(safi_str);

	assert(safi != SAFI_MAX);
	if (no)
		bgp->default_af[afi][safi] = false;
	else {
		if ((safi == SAFI_LABELED_UNICAST
		     && bgp->default_af[afi][SAFI_UNICAST])
		    || (safi == SAFI_UNICAST
			&& bgp->default_af[afi][SAFI_LABELED_UNICAST]))
			bgp_vty_return(vty, BGP_ERR_PEER_SAFI_CONFLICT);
		else
			bgp->default_af[afi][safi] = true;
	}

	return CMD_SUCCESS;
}

/* Display hostname in certain command outputs */
DEFUN (bgp_default_show_hostname,
       bgp_default_show_hostname_cmd,
       "bgp default show-hostname",
       BGP_STR
       "Configure BGP defaults\n"
       "Show hostname in certain command outputs\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	SET_FLAG(bgp->flags, BGP_FLAG_SHOW_HOSTNAME);
	return CMD_SUCCESS;
}

DEFUN (no_bgp_default_show_hostname,
       no_bgp_default_show_hostname_cmd,
       "no bgp default show-hostname",
       NO_STR
       BGP_STR
       "Configure BGP defaults\n"
       "Show hostname in certain command outputs\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	UNSET_FLAG(bgp->flags, BGP_FLAG_SHOW_HOSTNAME);
	return CMD_SUCCESS;
}

/* Display hostname in certain command outputs */
DEFUN (bgp_default_show_nexthop_hostname,
       bgp_default_show_nexthop_hostname_cmd,
       "bgp default show-nexthop-hostname",
       BGP_STR
       "Configure BGP defaults\n"
       "Show hostname for nexthop in certain command outputs\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	SET_FLAG(bgp->flags, BGP_FLAG_SHOW_NEXTHOP_HOSTNAME);
	return CMD_SUCCESS;
}

DEFUN (no_bgp_default_show_nexthop_hostname,
       no_bgp_default_show_nexthop_hostname_cmd,
       "no bgp default show-nexthop-hostname",
       NO_STR
       BGP_STR
       "Configure BGP defaults\n"
       "Show hostname for nexthop in certain command outputs\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	UNSET_FLAG(bgp->flags, BGP_FLAG_SHOW_NEXTHOP_HOSTNAME);
	return CMD_SUCCESS;
}

DEFPY (bgp_default_software_version_capability,
       bgp_default_software_version_capability_cmd,
       "[no] bgp default software-version-capability",
       NO_STR
       BGP_STR
       "Configure BGP defaults\n"
       "Advertise software version capability for all neighbors\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	if (no)
		UNSET_FLAG(bgp->flags, BGP_FLAG_SOFT_VERSION_CAPABILITY);
	else
		SET_FLAG(bgp->flags, BGP_FLAG_SOFT_VERSION_CAPABILITY);

	return CMD_SUCCESS;
}

DEFPY (bgp_default_dynamic_capability,
       bgp_default_dynamic_capability_cmd,
       "[no] bgp default dynamic-capability",
       NO_STR
       BGP_STR
       "Configure BGP defaults\n"
       "Advertise dynamic capability for all neighbors\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	if (no)
		UNSET_FLAG(bgp->flags, BGP_FLAG_DYNAMIC_CAPABILITY);
	else
		SET_FLAG(bgp->flags, BGP_FLAG_DYNAMIC_CAPABILITY);

	return CMD_SUCCESS;
}

/* "bgp network import-check" configuration.  */
DEFUN (bgp_network_import_check,
       bgp_network_import_check_cmd,
       "bgp network import-check",
       BGP_STR
       "BGP network command\n"
       "Check BGP network route exists in IGP\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	if (!CHECK_FLAG(bgp->flags, BGP_FLAG_IMPORT_CHECK)) {
		SET_FLAG(bgp->flags, BGP_FLAG_IMPORT_CHECK);
		bgp_static_redo_import_check(bgp);
	}

	return CMD_SUCCESS;
}

DEFUN (no_bgp_network_import_check,
       no_bgp_network_import_check_cmd,
       "no bgp network import-check",
       NO_STR
       BGP_STR
       "BGP network command\n"
       "Check BGP network route exists in IGP\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	if (CHECK_FLAG(bgp->flags, BGP_FLAG_IMPORT_CHECK)) {
		UNSET_FLAG(bgp->flags, BGP_FLAG_IMPORT_CHECK);
		bgp_static_redo_import_check(bgp);
	}

	return CMD_SUCCESS;
}

DEFUN (bgp_default_local_preference,
       bgp_default_local_preference_cmd,
       "bgp default local-preference (0-4294967295)",
       BGP_STR
       "Configure BGP defaults\n"
       "local preference (higher=more preferred)\n"
       "Configure default local preference value\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_number = 3;
	uint32_t local_pref;

	local_pref = strtoul(argv[idx_number]->arg, NULL, 10);

	bgp_default_local_preference_set(bgp, local_pref);
	bgp_clear_star_soft_in(vty, bgp->name);

	return CMD_SUCCESS;
}

DEFUN (no_bgp_default_local_preference,
       no_bgp_default_local_preference_cmd,
       "no bgp default local-preference [(0-4294967295)]",
       NO_STR
       BGP_STR
       "Configure BGP defaults\n"
       "local preference (higher=more preferred)\n"
       "Configure default local preference value\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	bgp_default_local_preference_unset(bgp);
	bgp_clear_star_soft_in(vty, bgp->name);

	return CMD_SUCCESS;
}


DEFUN (bgp_default_subgroup_pkt_queue_max,
       bgp_default_subgroup_pkt_queue_max_cmd,
       "bgp default subgroup-pkt-queue-max (20-100)",
       BGP_STR
       "Configure BGP defaults\n"
       "subgroup-pkt-queue-max\n"
       "Configure subgroup packet queue max\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_number = 3;
	uint32_t max_size;

	max_size = strtoul(argv[idx_number]->arg, NULL, 10);

	bgp_default_subgroup_pkt_queue_max_set(bgp, max_size);

	return CMD_SUCCESS;
}

DEFUN (no_bgp_default_subgroup_pkt_queue_max,
       no_bgp_default_subgroup_pkt_queue_max_cmd,
       "no bgp default subgroup-pkt-queue-max [(20-100)]",
       NO_STR
       BGP_STR
       "Configure BGP defaults\n"
       "subgroup-pkt-queue-max\n"
       "Configure subgroup packet queue max\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	bgp_default_subgroup_pkt_queue_max_unset(bgp);
	return CMD_SUCCESS;
}


DEFUN (bgp_rr_allow_outbound_policy,
       bgp_rr_allow_outbound_policy_cmd,
       "bgp route-reflector allow-outbound-policy",
       BGP_STR
       "Allow modifications made by out route-map\n"
       "on ibgp neighbors\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	if (!CHECK_FLAG(bgp->flags, BGP_FLAG_RR_ALLOW_OUTBOUND_POLICY)) {
		SET_FLAG(bgp->flags, BGP_FLAG_RR_ALLOW_OUTBOUND_POLICY);
		update_group_announce_rrclients(bgp);
		bgp_clear_star_soft_out(vty, bgp->name);
	}

	return CMD_SUCCESS;
}

DEFUN (no_bgp_rr_allow_outbound_policy,
       no_bgp_rr_allow_outbound_policy_cmd,
       "no bgp route-reflector allow-outbound-policy",
       NO_STR
       BGP_STR
       "Allow modifications made by out route-map\n"
       "on ibgp neighbors\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	if (CHECK_FLAG(bgp->flags, BGP_FLAG_RR_ALLOW_OUTBOUND_POLICY)) {
		UNSET_FLAG(bgp->flags, BGP_FLAG_RR_ALLOW_OUTBOUND_POLICY);
		update_group_announce_rrclients(bgp);
		bgp_clear_star_soft_out(vty, bgp->name);
	}

	return CMD_SUCCESS;
}

DEFUN (bgp_listen_limit,
       bgp_listen_limit_cmd,
       "bgp listen limit (1-65535)",
       BGP_STR
       "BGP Dynamic Neighbors listen commands\n"
       "Maximum number of BGP Dynamic Neighbors that can be created\n"
       "Configure Dynamic Neighbors listen limit value\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_number = 3;
	int listen_limit;

	listen_limit = strtoul(argv[idx_number]->arg, NULL, 10);

	bgp_listen_limit_set(bgp, listen_limit);

	return CMD_SUCCESS;
}

DEFUN (no_bgp_listen_limit,
       no_bgp_listen_limit_cmd,
       "no bgp listen limit [(1-65535)]",
       NO_STR
       BGP_STR
       "BGP Dynamic Neighbors listen commands\n"
       "Maximum number of BGP Dynamic Neighbors that can be created\n"
       "Configure Dynamic Neighbors listen limit value\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	bgp_listen_limit_unset(bgp);
	return CMD_SUCCESS;
}


/*
 * Check if this listen range is already configured. Check for exact
 * match or overlap based on input.
 */
static struct peer_group *listen_range_exists(struct bgp *bgp,
					      struct prefix *range, int exact)
{
	struct listnode *node, *nnode;
	struct listnode *node1, *nnode1;
	struct peer_group *group;
	struct prefix *lr;
	afi_t afi;
	int match;

	afi = family2afi(range->family);
	for (ALL_LIST_ELEMENTS(bgp->group, node, nnode, group)) {
		for (ALL_LIST_ELEMENTS(group->listen_range[afi], node1, nnode1,
				       lr)) {
			if (exact)
				match = prefix_same(range, lr);
			else
				match = (prefix_match(range, lr)
					 || prefix_match(lr, range));
			if (match)
				return group;
		}
	}

	return NULL;
}

DEFUN (bgp_listen_range,
       bgp_listen_range_cmd,
       "bgp listen range <A.B.C.D/M|X:X::X:X/M> peer-group PGNAME",
       BGP_STR
       "Configure BGP dynamic neighbors listen range\n"
       "Configure BGP dynamic neighbors listen range\n"
       NEIGHBOR_ADDR_STR
       "Member of the peer-group\n"
       "Peer-group name\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	struct prefix range;
	struct peer_group *group, *existing_group;
	afi_t afi;
	int ret;
	int idx = 0;

	argv_find(argv, argc, "A.B.C.D/M", &idx);
	argv_find(argv, argc, "X:X::X:X/M", &idx);
	char *prefix = argv[idx]->arg;
	argv_find(argv, argc, "PGNAME", &idx);
	char *peergroup = argv[idx]->arg;

	/* Convert IP prefix string to struct prefix. */
	ret = str2prefix(prefix, &range);
	if (!ret) {
		vty_out(vty, "%% Malformed listen range\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	afi = family2afi(range.family);

	if (afi == AFI_IP6 && IN6_IS_ADDR_LINKLOCAL(&range.u.prefix6)) {
		vty_out(vty,
			"%% Malformed listen range (link-local address)\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	apply_mask(&range);

	/* Check if same listen range is already configured. */
	existing_group = listen_range_exists(bgp, &range, 1);
	if (existing_group) {
		if (strcmp(existing_group->name, peergroup) == 0)
			return CMD_SUCCESS;
		else {
			vty_out(vty,
				"%% Same listen range is attached to peer-group %s\n",
				existing_group->name);
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	/* Check if an overlapping listen range exists. */
	if (listen_range_exists(bgp, &range, 0)) {
		vty_out(vty,
			"%% Listen range overlaps with existing listen range\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	group = peer_group_lookup(bgp, peergroup);
	if (!group) {
		vty_out(vty, "%% Configure the peer-group first\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ret = peer_group_listen_range_add(group, &range);
	return bgp_vty_return(vty, ret);
}

DEFUN (no_bgp_listen_range,
       no_bgp_listen_range_cmd,
       "no bgp listen range <A.B.C.D/M|X:X::X:X/M> peer-group PGNAME",
       NO_STR
       BGP_STR
       "Unconfigure BGP dynamic neighbors listen range\n"
       "Unconfigure BGP dynamic neighbors listen range\n"
       NEIGHBOR_ADDR_STR
       "Member of the peer-group\n"
       "Peer-group name\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	struct prefix range;
	struct peer_group *group;
	afi_t afi;
	int ret;
	int idx = 0;

	argv_find(argv, argc, "A.B.C.D/M", &idx);
	argv_find(argv, argc, "X:X::X:X/M", &idx);
	char *prefix = argv[idx]->arg;
	argv_find(argv, argc, "PGNAME", &idx);
	char *peergroup = argv[idx]->arg;

	/* Convert IP prefix string to struct prefix. */
	ret = str2prefix(prefix, &range);
	if (!ret) {
		vty_out(vty, "%% Malformed listen range\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	afi = family2afi(range.family);

	if (afi == AFI_IP6 && IN6_IS_ADDR_LINKLOCAL(&range.u.prefix6)) {
		vty_out(vty,
			"%% Malformed listen range (link-local address)\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	apply_mask(&range);

	group = peer_group_lookup(bgp, peergroup);
	if (!group) {
		vty_out(vty, "%% Peer-group does not exist\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ret = peer_group_listen_range_del(group, &range);
	return bgp_vty_return(vty, ret);
}

void bgp_config_write_listen(struct vty *vty, struct bgp *bgp)
{
	struct peer_group *group;
	struct listnode *node, *nnode, *rnode, *nrnode;
	struct prefix *range;
	afi_t afi;

	if (bgp->dynamic_neighbors_limit != BGP_DYNAMIC_NEIGHBORS_LIMIT_DEFAULT)
		vty_out(vty, " bgp listen limit %d\n",
			bgp->dynamic_neighbors_limit);

	for (ALL_LIST_ELEMENTS(bgp->group, node, nnode, group)) {
		for (afi = AFI_IP; afi < AFI_MAX; afi++) {
			for (ALL_LIST_ELEMENTS(group->listen_range[afi], rnode,
					       nrnode, range)) {
				vty_out(vty,
					" bgp listen range %pFX peer-group %s\n",
					range, group->name);
			}
		}
	}
}


DEFUN (bgp_disable_connected_route_check,
       bgp_disable_connected_route_check_cmd,
       "bgp disable-ebgp-connected-route-check",
       BGP_STR
       "Disable checking if nexthop is connected on ebgp sessions\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	SET_FLAG(bgp->flags, BGP_FLAG_DISABLE_NH_CONNECTED_CHK);
	bgp_clear_star_soft_in(vty, bgp->name);

	return CMD_SUCCESS;
}

DEFUN (no_bgp_disable_connected_route_check,
       no_bgp_disable_connected_route_check_cmd,
       "no bgp disable-ebgp-connected-route-check",
       NO_STR
       BGP_STR
       "Disable checking if nexthop is connected on ebgp sessions\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	UNSET_FLAG(bgp->flags, BGP_FLAG_DISABLE_NH_CONNECTED_CHK);
	bgp_clear_star_soft_in(vty, bgp->name);

	return CMD_SUCCESS;
}


static int peer_remote_as_vty(struct vty *vty, const char *peer_str,
			      const char *as_str)
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int ret;
	as_t as;
	enum peer_asn_type as_type = AS_SPECIFIED;
	union sockunion su;

	if (as_str[0] == 'i') {
		as = 0;
		as_type = AS_INTERNAL;
	} else if (as_str[0] == 'e') {
		as = 0;
		as_type = AS_EXTERNAL;
	} else if (as_str[0] == 'a') {
		as = 0;
		as_type = AS_AUTO;
	} else if (!asn_str2asn(as_str, &as))
		as_type = AS_UNSPECIFIED;

	if (as_type == AS_UNSPECIFIED) {
		vty_out(vty, "%% Invalid peer AS: %s\n", as_str);
		return CMD_WARNING_CONFIG_FAILED;
	}
	/* If peer is peer group or interface peer, call proper function. */
	ret = str2sockunion(peer_str, &su);
	if (ret < 0) {
		struct peer *peer;

		/* Check if existing interface peer */
		peer = peer_lookup_by_conf_if(bgp, peer_str);

		ret = peer_remote_as(bgp, NULL, peer_str, &as, as_type, as_str);

		/* if not interface peer, check peer-group settings */
		if (ret < 0 && !peer) {
			ret = peer_group_remote_as(bgp, peer_str, &as, as_type,
						   as_str);
			if (ret < 0) {
				vty_out(vty,
					"%% Create the peer-group or interface first\n");
				return CMD_WARNING_CONFIG_FAILED;
			}
			return CMD_SUCCESS;
		}
	} else {
		if (peer_address_self_check(bgp, &su)) {
			vty_out(vty,
				"%% Can not configure the local system as neighbor\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		ret = peer_remote_as(bgp, &su, NULL, &as, as_type, as_str);
	}

	return bgp_vty_return(vty, ret);
}

DEFUN (bgp_default_shutdown,
       bgp_default_shutdown_cmd,
       "[no] bgp default shutdown",
       NO_STR
       BGP_STR
       "Configure BGP defaults\n"
       "Apply administrative shutdown to newly configured peers\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	bgp->autoshutdown = !strmatch(argv[0]->text, "no");
	return CMD_SUCCESS;
}

DEFPY(bgp_shutdown_msg, bgp_shutdown_msg_cmd, "bgp shutdown message MSG...",
      BGP_STR
      "Administrative shutdown of the BGP instance\n"
      "Add a shutdown message (RFC 8203)\n"
      "Shutdown message\n")
{
	char *msgstr = NULL;

	VTY_DECLVAR_CONTEXT(bgp, bgp);

	if (argc > 3)
		msgstr = argv_concat(argv, argc, 3);

	if (msgstr && strlen(msgstr) > BGP_ADMIN_SHUTDOWN_MSG_LEN) {
		vty_out(vty, "%% Shutdown message size exceeded %d\n",
			BGP_ADMIN_SHUTDOWN_MSG_LEN);
		return CMD_WARNING_CONFIG_FAILED;
	}

	bgp_shutdown_enable(bgp, msgstr);
	XFREE(MTYPE_TMP, msgstr);

	return CMD_SUCCESS;
}

DEFPY(bgp_shutdown, bgp_shutdown_cmd, "bgp shutdown",
      BGP_STR "Administrative shutdown of the BGP instance\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	bgp_shutdown_enable(bgp, NULL);

	return CMD_SUCCESS;
}

DEFPY(no_bgp_shutdown, no_bgp_shutdown_cmd, "no bgp shutdown",
      NO_STR BGP_STR "Administrative shutdown of the BGP instance\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	bgp_shutdown_disable(bgp);

	return CMD_SUCCESS;
}

ALIAS(no_bgp_shutdown, no_bgp_shutdown_msg_cmd,
      "no bgp shutdown message MSG...", NO_STR BGP_STR
      "Administrative shutdown of the BGP instance\n"
      "Add a shutdown message (RFC 8203)\n" "Shutdown message\n")

DEFUN (neighbor_remote_as,
       neighbor_remote_as_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> remote-as <ASNUM|internal|external|auto>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Specify a BGP neighbor\n"
       AS_STR
       "Internal BGP peer\n"
       "External BGP peer\n"
       "Automatically detect remote ASN\n")
{
	int idx_peer = 1;
	int idx_remote_as = 3;
	return peer_remote_as_vty(vty, argv[idx_peer]->arg,
				  argv[idx_remote_as]->arg);
}

DEFPY (bgp_allow_martian,
       bgp_allow_martian_cmd,
       "[no]$no bgp allow-martian-nexthop",
       NO_STR
       BGP_STR
       "Allow Martian nexthops to be received in the NLRI from a peer\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	if (no)
		bgp->allow_martian = false;
	else
		bgp->allow_martian = true;

	return CMD_SUCCESS;
}

/* Enable fast convergence of bgp sessions. If this is enabled, bgp
 * sessions do not wait for hold timer expiry to bring down the sessions
 * when nexthop becomes unreachable
 */
DEFUN(bgp_fast_convergence, bgp_fast_convergence_cmd, "bgp fast-convergence",
      BGP_STR "Fast convergence for bgp sessions\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	bgp->fast_convergence = true;

	return CMD_SUCCESS;
}

DEFUN(no_bgp_fast_convergence, no_bgp_fast_convergence_cmd,
      "no bgp fast-convergence",
      NO_STR BGP_STR "Fast convergence for bgp sessions\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	bgp->fast_convergence = false;

	return CMD_SUCCESS;
}

DEFPY (bgp_ipv6_auto_ra,
       bgp_ipv6_auto_ra_cmd,
       "[no] bgp ipv6-auto-ra",
       NO_STR
       BGP_STR
       "Allow enabling IPv6 ND RA sending\n")
{
	if (vty->node == CONFIG_NODE) {
		struct listnode *node, *nnode;
		struct bgp *bgp;

		COND_FLAG(bm->flags, BM_FLAG_IPV6_NO_AUTO_RA, no);
		for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp))
			COND_FLAG(bgp->flags, BGP_FLAG_IPV6_NO_AUTO_RA, no);
	} else {
		VTY_DECLVAR_CONTEXT(bgp, bgp);
		COND_FLAG(bgp->flags, BGP_FLAG_IPV6_NO_AUTO_RA, no);
	}
	return CMD_SUCCESS;
}

static int peer_conf_interface_get(struct vty *vty, const char *conf_if,
				   int v6only,
				   const char *peer_group_name,
				   const char *as_str)
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	as_t as = 0;
	enum peer_asn_type as_type = AS_UNSPECIFIED;
	struct peer *peer;
	struct peer_group *group;
	int ret = 0;

	group = peer_group_lookup(bgp, conf_if);

	if (group) {
		vty_out(vty, "%% Name conflict with peer-group \n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (as_str) {
		if (as_str[0] == 'i') {
			as_type = AS_INTERNAL;
		} else if (as_str[0] == 'e') {
			as_type = AS_EXTERNAL;
		} else if (as_str[0] == 'a') {
			as_type = AS_AUTO;
		} else {
			/* Get AS number.  */
			if (asn_str2asn(as_str, &as))
				as_type = AS_SPECIFIED;
		}
	}

	peer = peer_lookup_by_conf_if(bgp, conf_if);
	if (peer) {
		if (as_str)
			ret = peer_remote_as(bgp, NULL, conf_if, &as, as_type,
					     as_str);
	} else {
		peer = peer_create(NULL, conf_if, bgp, bgp->as, as, as_type,
				   NULL, true, as_str);

		if (!peer) {
			vty_out(vty, "%% BGP failed to create peer\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		if (v6only)
			peer_flag_set(peer, PEER_FLAG_IFPEER_V6ONLY);

		/* Request zebra to initiate IPv6 RAs on this interface. We do
		 * this
		 * any unnumbered peer in order to not worry about run-time
		 * transitions
		 * (e.g., peering is initially IPv4, but the IPv4 /30 or /31
		 * address
		 * gets deleted later etc.)
		 */
		if (peer->ifp)
			bgp_zebra_initiate_radv(bgp, peer);
	}

	if ((v6only && !CHECK_FLAG(peer->flags, PEER_FLAG_IFPEER_V6ONLY))
	    || (!v6only && CHECK_FLAG(peer->flags, PEER_FLAG_IFPEER_V6ONLY))) {
		if (v6only)
			peer_flag_set(peer, PEER_FLAG_IFPEER_V6ONLY);
		else
			peer_flag_unset(peer, PEER_FLAG_IFPEER_V6ONLY);

		peer->last_reset = PEER_DOWN_V6ONLY_CHANGE;

		/* v6only flag changed. Reset bgp seesion */
		if (BGP_IS_VALID_STATE_FOR_NOTIF(peer->connection->status))
			bgp_notify_send(peer->connection, BGP_NOTIFY_CEASE,
					BGP_NOTIFY_CEASE_CONFIG_CHANGE);
		else
			bgp_session_reset(peer);
	}

	if (!CHECK_FLAG(peer->flags_invert, PEER_FLAG_CAPABILITY_ENHE)) {
		SET_FLAG(peer->flags, PEER_FLAG_CAPABILITY_ENHE);
		SET_FLAG(peer->flags_invert, PEER_FLAG_CAPABILITY_ENHE);
		SET_FLAG(peer->flags_override, PEER_FLAG_CAPABILITY_ENHE);
	}

	if (peer_group_name) {
		group = peer_group_lookup(bgp, peer_group_name);
		if (!group) {
			vty_out(vty, "%% Configure the peer-group first\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		ret = peer_group_bind(bgp, NULL, peer, group, &as);
	}

	return bgp_vty_return(vty, ret);
}

DEFUN (neighbor_interface_config,
       neighbor_interface_config_cmd,
       "neighbor WORD interface [peer-group PGNAME]",
       NEIGHBOR_STR
       "Interface name or neighbor tag\n"
       "Enable BGP on interface\n"
       "Member of the peer-group\n"
       "Peer-group name\n")
{
	int idx_word = 1;
	int idx_peer_group_word = 4;

	if (argc > idx_peer_group_word)
		return peer_conf_interface_get(
			vty, argv[idx_word]->arg, 0,
			argv[idx_peer_group_word]->arg, NULL);
	else
		return peer_conf_interface_get(vty, argv[idx_word]->arg, 0,
					       NULL, NULL);
}

DEFUN (neighbor_interface_config_v6only,
       neighbor_interface_config_v6only_cmd,
       "neighbor WORD interface v6only [peer-group PGNAME]",
       NEIGHBOR_STR
       "Interface name or neighbor tag\n"
       "Enable BGP on interface\n"
       "Enable BGP with v6 link-local only\n"
       "Member of the peer-group\n"
       "Peer-group name\n")
{
	int idx_word = 1;
	int idx_peer_group_word = 5;

	if (argc > idx_peer_group_word)
		return peer_conf_interface_get(
			vty, argv[idx_word]->arg, 1,
			argv[idx_peer_group_word]->arg, NULL);

	return peer_conf_interface_get(vty, argv[idx_word]->arg, 1, NULL, NULL);
}


DEFUN (neighbor_interface_config_remote_as,
       neighbor_interface_config_remote_as_cmd,
       "neighbor WORD interface remote-as <ASNUM|internal|external|auto>",
       NEIGHBOR_STR
       "Interface name or neighbor tag\n"
       "Enable BGP on interface\n"
       "Specify a BGP neighbor\n"
       AS_STR
       "Internal BGP peer\n"
       "External BGP peer\n"
       "Automatically detect remote ASN\n")
{
	int idx_word = 1;
	int idx_remote_as = 4;
	return peer_conf_interface_get(vty, argv[idx_word]->arg, 0, NULL,
				       argv[idx_remote_as]->arg);
}

DEFUN (neighbor_interface_v6only_config_remote_as,
       neighbor_interface_v6only_config_remote_as_cmd,
       "neighbor WORD interface v6only remote-as <ASNUM|internal|external|auto>",
       NEIGHBOR_STR
       "Interface name or neighbor tag\n"
       "Enable BGP with v6 link-local only\n"
       "Enable BGP on interface\n"
       "Specify a BGP neighbor\n"
       AS_STR
       "Internal BGP peer\n"
       "External BGP peer\n"
       "Automatically detect remote ASN\n")
{
	int idx_word = 1;
	int idx_remote_as = 5;
	return peer_conf_interface_get(vty, argv[idx_word]->arg, 1, NULL,
				       argv[idx_remote_as]->arg);
}

DEFUN (neighbor_peer_group,
       neighbor_peer_group_cmd,
       "neighbor WORD peer-group",
       NEIGHBOR_STR
       "Interface name or neighbor tag\n"
       "Configure peer-group\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_word = 1;
	struct peer *peer;
	struct peer_group *group;

	peer = peer_lookup_by_conf_if(bgp, argv[idx_word]->arg);
	if (peer) {
		vty_out(vty, "%% Name conflict with interface: \n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	group = peer_group_get(bgp, argv[idx_word]->arg);
	if (!group) {
		vty_out(vty, "%% BGP failed to find or create peer-group\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	return CMD_SUCCESS;
}

DEFUN (no_neighbor,
       no_neighbor_cmd,
       "no neighbor <WORD|<A.B.C.D|X:X::X:X> [remote-as <(1-4294967295)|internal|external|auto>]>",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Specify a BGP neighbor\n"
       AS_STR
       "Internal BGP peer\n"
       "External BGP peer\n"
       "Automatically detect remote ASN\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_peer = 2;
	int ret;
	union sockunion su;
	struct peer_group *group;
	struct peer *peer;
	struct peer *other;
	afi_t afi;
	int lr_count;

	ret = str2sockunion(argv[idx_peer]->arg, &su);
	if (ret < 0) {
		/* look up for neighbor by interface name config. */
		peer = peer_lookup_by_conf_if(bgp, argv[idx_peer]->arg);
		if (peer) {
			/* Request zebra to terminate IPv6 RAs on this
			 * interface. */
			if (peer->ifp)
				bgp_zebra_terminate_radv(peer->bgp, peer);
			peer_notify_unconfig(peer);
			peer_delete(peer);
			return CMD_SUCCESS;
		}

		group = peer_group_lookup(bgp, argv[idx_peer]->arg);
		if (group) {
			for (afi = AFI_IP; afi < AFI_MAX; afi++) {
				lr_count = listcount(group->listen_range[afi]);
				if (lr_count) {
					vty_out(vty,
						"%%Peer-group %s is attached to %d listen-range(s), delete them first\n",
						group->name, lr_count);
					return CMD_WARNING_CONFIG_FAILED;
				}
			}
			peer_group_notify_unconfig(group);
			peer_group_delete(group);
		} else {
			vty_out(vty, "%% Create the peer-group first\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	} else {
		peer = peer_lookup(bgp, &su);
		if (peer) {
			if (peer_dynamic_neighbor(peer)) {
				vty_out(vty,
					"%% Operation not allowed on a dynamic neighbor\n");
				return CMD_WARNING_CONFIG_FAILED;
			}

			other = peer->doppelganger;

			if (CHECK_FLAG(peer->flags, PEER_FLAG_CAPABILITY_ENHE))
				bgp_zebra_terminate_radv(peer->bgp, peer);

			peer_notify_unconfig(peer);
			peer_delete(peer);
			if (other && other->connection->status != Deleted) {
				peer_notify_unconfig(other);
				peer_delete(other);
			}
		}
	}

	return CMD_SUCCESS;
}

DEFUN (no_neighbor_interface_config,
       no_neighbor_interface_config_cmd,
       "no neighbor WORD interface [v6only] [peer-group PGNAME] [remote-as <(1-4294967295)|internal|external|auto>]",
       NO_STR
       NEIGHBOR_STR
       "Interface name\n"
       "Configure BGP on interface\n"
       "Enable BGP with v6 link-local only\n"
       "Member of the peer-group\n"
       "Peer-group name\n"
       "Specify a BGP neighbor\n"
       AS_STR
       "Internal BGP peer\n"
       "External BGP peer\n"
       "Automatically detect remote ASN\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_word = 2;
	struct peer *peer;

	/* look up for neighbor by interface name config. */
	peer = peer_lookup_by_conf_if(bgp, argv[idx_word]->arg);
	if (peer) {
		/* Request zebra to terminate IPv6 RAs on this interface. */
		if (peer->ifp)
			bgp_zebra_terminate_radv(peer->bgp, peer);
		peer_notify_unconfig(peer);
		peer_delete(peer);
	} else {
		vty_out(vty, "%% Create the bgp interface first\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	return CMD_SUCCESS;
}

DEFUN (no_neighbor_peer_group,
       no_neighbor_peer_group_cmd,
       "no neighbor WORD peer-group",
       NO_STR
       NEIGHBOR_STR
       "Neighbor tag\n"
       "Configure peer-group\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_word = 2;
	struct peer_group *group;
	afi_t afi;
	int lr_count;

	group = peer_group_lookup(bgp, argv[idx_word]->arg);
	if (group) {
		for (afi = AFI_IP; afi < AFI_MAX; afi++) {
			lr_count = listcount(group->listen_range[afi]);
			if (lr_count) {
				vty_out(vty,
					"%%Peer-group %s is attached to %d listen-range(s), delete them first\n",
					group->name, lr_count);
				return CMD_WARNING_CONFIG_FAILED;
			}
		}
		peer_group_notify_unconfig(group);
		peer_group_delete(group);
	} else {
		vty_out(vty, "%% Create the peer-group first\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	return CMD_SUCCESS;
}

DEFUN (no_neighbor_interface_peer_group_remote_as,
       no_neighbor_interface_peer_group_remote_as_cmd,
       "no neighbor WORD remote-as <ASNUM|internal|external|auto>",
       NO_STR
       NEIGHBOR_STR
       "Interface name or neighbor tag\n"
       "Specify a BGP neighbor\n"
       AS_STR
       "Internal BGP peer\n"
       "External BGP peer\n"
       "Automatically detect remote ASN\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_word = 2;
	struct peer_group *group;
	struct peer *peer;

	/* look up for neighbor by interface name config. */
	peer = peer_lookup_by_conf_if(bgp, argv[idx_word]->arg);
	if (peer) {
		peer_as_change(peer, 0, AS_UNSPECIFIED, NULL);
		return CMD_SUCCESS;
	}

	group = peer_group_lookup(bgp, argv[idx_word]->arg);
	if (group)
		peer_group_remote_as_delete(group);
	else {
		vty_out(vty, "%% Create the peer-group or interface first\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	return CMD_SUCCESS;
}

DEFUN (neighbor_local_as,
       neighbor_local_as_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> local-as ASNUM",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Specify a local-as number\n"
       "AS number expressed in dotted or plain format used as local AS\n")
{
	int idx_peer = 1;
	int idx_number = 3;
	struct peer *peer;
	int ret;
	as_t as;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	if (!asn_str2asn(argv[idx_number]->arg, &as)) {
		vty_out(vty, "%% Invalid neighbor local-as value: %s\n",
			argv[idx_number]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	ret = peer_local_as_set(peer, as, 0, 0, 0, argv[idx_number]->arg);
	return bgp_vty_return(vty, ret);
}

DEFUN (neighbor_local_as_no_prepend,
       neighbor_local_as_no_prepend_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> local-as ASNUM no-prepend",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Specify a local-as number\n"
       "AS number expressed in dotted or plain format used as local AS\n"
       "Do not prepend local-as to updates from ebgp peers\n")
{
	int idx_peer = 1;
	int idx_number = 3;
	struct peer *peer;
	int ret;
	as_t as;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	if (!asn_str2asn(argv[idx_number]->arg, &as)) {
		vty_out(vty, "%% Invalid neighbor local-as value: %s\n",
			argv[idx_number]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	ret = peer_local_as_set(peer, as, 1, 0, 0, argv[idx_number]->arg);
	return bgp_vty_return(vty, ret);
}

DEFPY (neighbor_local_as_no_prepend_replace_as,
       neighbor_local_as_no_prepend_replace_as_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> local-as ASNUM no-prepend replace-as [dual-as$dual_as]",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Specify a local-as number\n"
       "AS number expressed in dotted or plain format used as local AS\n"
       "Do not prepend local-as to updates from ebgp peers\n"
       "Do not prepend local-as to updates from ibgp peers\n"
       "Allow peering with a global AS number or local-as number\n")
{
	int idx_peer = 1;
	int idx_number = 3;
	struct peer *peer;
	int ret;
	as_t as;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	if (!asn_str2asn(argv[idx_number]->arg, &as)) {
		vty_out(vty, "%% Invalid neighbor local-as value: %s\n",
			argv[idx_number]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	ret = peer_local_as_set(peer, as, 1, 1, dual_as, argv[idx_number]->arg);
	return bgp_vty_return(vty, ret);
}

DEFUN (no_neighbor_local_as,
       no_neighbor_local_as_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> local-as [ASNUM [no-prepend [replace-as] [dual-as]]]",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Specify a local-as number\n"
       "AS number expressed in dotted or plain format used as local AS\n"
       "Do not prepend local-as to updates from ebgp peers\n"
       "Do not prepend local-as to updates from ibgp peers\n"
       "Allow peering with a global AS number or local-as number\n")
{
	int idx_peer = 2;
	struct peer *peer;
	int ret;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	ret = peer_local_as_unset(peer);
	return bgp_vty_return(vty, ret);
}


DEFUN (neighbor_solo,
       neighbor_solo_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> solo",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Solo peer - part of its own update group\n")
{
	int idx_peer = 1;
	struct peer *peer;
	int ret;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	ret = update_group_adjust_soloness(peer, 1);
	return bgp_vty_return(vty, ret);
}

DEFUN (no_neighbor_solo,
       no_neighbor_solo_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> solo",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Solo peer - part of its own update group\n")
{
	int idx_peer = 2;
	struct peer *peer;
	int ret;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	ret = update_group_adjust_soloness(peer, 0);
	return bgp_vty_return(vty, ret);
}

DEFUN (neighbor_password,
       neighbor_password_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> password LINE",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Set a password\n"
       "The password\n")
{
	int idx_peer = 1;
	int idx_line = 3;
	struct peer *peer;
	int ret;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	ret = peer_password_set(peer, argv[idx_line]->arg);
	return bgp_vty_return(vty, ret);
}

DEFUN (no_neighbor_password,
       no_neighbor_password_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> password [LINE]",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Set a password\n"
       "The password\n")
{
	int idx_peer = 2;
	struct peer *peer;
	int ret;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	ret = peer_password_unset(peer);
	return bgp_vty_return(vty, ret);
}

DEFUN (neighbor_activate,
       neighbor_activate_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> activate",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Enable the Address Family for this Neighbor\n")
{
	int idx_peer = 1;
	int ret;
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	ret = peer_activate(peer, bgp_node_afi(vty), bgp_node_safi(vty));
	return bgp_vty_return(vty, ret);
}

ALIAS_HIDDEN(neighbor_activate, neighbor_activate_hidden_cmd,
	     "neighbor <A.B.C.D|X:X::X:X|WORD> activate",
	     NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Enable the Address Family for this Neighbor\n")

DEFUN (no_neighbor_activate,
       no_neighbor_activate_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> activate",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Enable the Address Family for this Neighbor\n")
{
	int idx_peer = 2;
	int ret;
	struct peer *peer;

	/* Lookup peer. */
	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	ret = peer_deactivate(peer, bgp_node_afi(vty), bgp_node_safi(vty));
	return bgp_vty_return(vty, ret);
}

ALIAS_HIDDEN(no_neighbor_activate, no_neighbor_activate_hidden_cmd,
	     "no neighbor <A.B.C.D|X:X::X:X|WORD> activate",
	     NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Enable the Address Family for this Neighbor\n")

DEFUN (neighbor_set_peer_group,
       neighbor_set_peer_group_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> peer-group PGNAME",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Member of the peer-group\n"
       "Peer-group name\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_peer = 1;
	int idx_word = 3;
	int ret;
	as_t as;
	union sockunion su;
	struct peer *peer;
	struct peer_group *group;

	ret = str2sockunion(argv[idx_peer]->arg, &su);
	if (ret < 0) {
		peer = peer_lookup_by_conf_if(bgp, argv[idx_peer]->arg);
		if (!peer) {
			vty_out(vty, "%% Malformed address or name: %s\n",
				argv[idx_peer]->arg);
			return CMD_WARNING_CONFIG_FAILED;
		}
	} else {
		if (peer_address_self_check(bgp, &su)) {
			vty_out(vty,
				"%% Can not configure the local system as neighbor\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		/* Disallow for dynamic neighbor. */
		peer = peer_lookup(bgp, &su);
		if (peer && peer_dynamic_neighbor(peer)) {
			vty_out(vty,
				"%% Operation not allowed on a dynamic neighbor\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	group = peer_group_lookup(bgp, argv[idx_word]->arg);
	if (!group) {
		vty_out(vty, "%% Configure the peer-group first\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ret = peer_group_bind(bgp, &su, peer, group, &as);

	return bgp_vty_return(vty, ret);
}

ALIAS_HIDDEN(neighbor_set_peer_group, neighbor_set_peer_group_hidden_cmd,
	     "neighbor <A.B.C.D|X:X::X:X|WORD> peer-group PGNAME",
	     NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Member of the peer-group\n"
	     "Peer-group name\n")

DEFUN (no_neighbor_set_peer_group,
       no_neighbor_set_peer_group_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> peer-group PGNAME",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Member of the peer-group\n"
       "Peer-group name\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_peer = 2;
	int idx_word = 4;
	int ret;
	struct peer *peer;
	struct peer_group *group;

	peer = peer_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	group = peer_group_lookup(bgp, argv[idx_word]->arg);
	if (!group) {
		vty_out(vty, "%% Configure the peer-group first\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (CHECK_FLAG(peer->flags, PEER_FLAG_CAPABILITY_ENHE))
		bgp_zebra_terminate_radv(peer->bgp, peer);

	peer_notify_unconfig(peer);
	ret = peer_delete(peer);

	return bgp_vty_return(vty, ret);
}

ALIAS_HIDDEN(no_neighbor_set_peer_group, no_neighbor_set_peer_group_hidden_cmd,
	     "no neighbor <A.B.C.D|X:X::X:X|WORD> peer-group PGNAME",
	     NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Member of the peer-group\n"
	     "Peer-group name\n")

/* neighbor passive. */
DEFUN (neighbor_passive,
       neighbor_passive_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> passive",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Don't send open messages to this neighbor\n")
{
	int idx_peer = 1;
	return peer_flag_set_vty(vty, argv[idx_peer]->arg, PEER_FLAG_PASSIVE);
}

DEFUN (no_neighbor_passive,
       no_neighbor_passive_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> passive",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Don't send open messages to this neighbor\n")
{
	int idx_peer = 2;
	return peer_flag_unset_vty(vty, argv[idx_peer]->arg, PEER_FLAG_PASSIVE);
}

/* neighbor shutdown. */
DEFUN (neighbor_shutdown_msg,
       neighbor_shutdown_msg_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> shutdown message MSG...",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Administratively shut down this neighbor\n"
       "Add a shutdown message (RFC 8203)\n"
       "Shutdown message\n")
{
	int idx_peer = 1;

	if (argc >= 5) {
		struct peer *peer =
			peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
		char *message;

		if (!peer)
			return CMD_WARNING_CONFIG_FAILED;
		message = argv_concat(argv, argc, 4);
		peer_tx_shutdown_message_set(peer, message);
		XFREE(MTYPE_TMP, message);
	}

	return peer_flag_set_vty(vty, argv[idx_peer]->arg, PEER_FLAG_SHUTDOWN);
}

ALIAS(neighbor_shutdown_msg, neighbor_shutdown_cmd,
      "neighbor <A.B.C.D|X:X::X:X|WORD> shutdown",
      NEIGHBOR_STR NEIGHBOR_ADDR_STR2
      "Administratively shut down this neighbor\n")

DEFUN (no_neighbor_shutdown_msg,
       no_neighbor_shutdown_msg_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> shutdown message MSG...",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Administratively shut down this neighbor\n"
       "Remove a shutdown message (RFC 8203)\n"
       "Shutdown message\n")
{
	int idx_peer = 2;

	return peer_flag_unset_vty(vty, argv[idx_peer]->arg,
				   PEER_FLAG_SHUTDOWN);
}

ALIAS(no_neighbor_shutdown_msg, no_neighbor_shutdown_cmd,
      "no neighbor <A.B.C.D|X:X::X:X|WORD> shutdown",
      NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
      "Administratively shut down this neighbor\n")

DEFUN(neighbor_shutdown_rtt,
      neighbor_shutdown_rtt_cmd,
      "neighbor <A.B.C.D|X:X::X:X|WORD> shutdown rtt (1-65535) [count (1-255)]",
      NEIGHBOR_STR
      NEIGHBOR_ADDR_STR2
      "Administratively shut down this neighbor\n"
      "Shutdown if round-trip-time is higher than expected\n"
      "Round-trip-time in milliseconds\n"
      "Specify the number of keepalives before shutdown\n"
      "The number of keepalives with higher RTT to shutdown\n")
{
	int idx_peer = 1;
	int idx_rtt = 4;
	int idx_count = 0;
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);

	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	peer->rtt_expected = strtol(argv[idx_rtt]->arg, NULL, 10);

	if (argv_find(argv, argc, "count", &idx_count))
		peer->rtt_keepalive_conf =
			strtol(argv[idx_count + 1]->arg, NULL, 10);

	return peer_flag_set_vty(vty, argv[idx_peer]->arg,
				 PEER_FLAG_RTT_SHUTDOWN);
}

DEFUN(no_neighbor_shutdown_rtt,
      no_neighbor_shutdown_rtt_cmd,
      "no neighbor <A.B.C.D|X:X::X:X|WORD> shutdown rtt [(1-65535) [count (1-255)]]",
      NO_STR
      NEIGHBOR_STR
      NEIGHBOR_ADDR_STR2
      "Administratively shut down this neighbor\n"
      "Shutdown if round-trip-time is higher than expected\n"
      "Round-trip-time in milliseconds\n"
      "Specify the number of keepalives before shutdown\n"
      "The number of keepalives with higher RTT to shutdown\n")
{
	int idx_peer = 2;
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);

	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	peer->rtt_expected = 0;
	peer->rtt_keepalive_conf = 1;

	return peer_flag_unset_vty(vty, argv[idx_peer]->arg,
				   PEER_FLAG_RTT_SHUTDOWN);
}

/* neighbor capability dynamic. */
DEFUN (neighbor_capability_dynamic,
       neighbor_capability_dynamic_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> capability dynamic",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Advertise capability to the peer\n"
       "Advertise dynamic capability to this neighbor\n")
{
	int idx_peer = 1;
	return peer_flag_set_vty(vty, argv[idx_peer]->arg,
				 PEER_FLAG_DYNAMIC_CAPABILITY);
}

DEFUN (no_neighbor_capability_dynamic,
       no_neighbor_capability_dynamic_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> capability dynamic",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Advertise capability to the peer\n"
       "Advertise dynamic capability to this neighbor\n")
{
	int idx_peer = 2;
	return peer_flag_unset_vty(vty, argv[idx_peer]->arg,
				   PEER_FLAG_DYNAMIC_CAPABILITY);
}

/* neighbor dont-capability-negotiate */
DEFUN (neighbor_dont_capability_negotiate,
       neighbor_dont_capability_negotiate_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> dont-capability-negotiate",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Do not perform capability negotiation\n")
{
	int idx_peer = 1;
	return peer_flag_set_vty(vty, argv[idx_peer]->arg,
				 PEER_FLAG_DONT_CAPABILITY);
}

DEFUN (no_neighbor_dont_capability_negotiate,
       no_neighbor_dont_capability_negotiate_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> dont-capability-negotiate",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Do not perform capability negotiation\n")
{
	int idx_peer = 2;
	return peer_flag_unset_vty(vty, argv[idx_peer]->arg,
				   PEER_FLAG_DONT_CAPABILITY);
}

/* neighbor capability fqdn */
DEFPY (neighbor_capability_fqdn,
       neighbor_capability_fqdn_cmd,
       "[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor capability fqdn",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Advertise capability to the peer\n"
       "Advertise fqdn capability to the peer\n")
{
	struct peer *peer;
	int ret;

	peer = peer_and_group_lookup_vty(vty, neighbor);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	if (no)
		ret = peer_flag_unset_vty(vty, neighbor,
					  PEER_FLAG_CAPABILITY_FQDN);
	else
		ret = peer_flag_set_vty(vty, neighbor,
					PEER_FLAG_CAPABILITY_FQDN);

	bgp_capability_send(peer, AFI_IP, SAFI_UNICAST, CAPABILITY_CODE_FQDN,
			    no ? CAPABILITY_ACTION_UNSET
			       : CAPABILITY_ACTION_SET);

	return ret;
}

/* neighbor capability extended next hop encoding */
DEFUN (neighbor_capability_enhe,
       neighbor_capability_enhe_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> capability extended-nexthop",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Advertise capability to the peer\n"
       "Advertise extended next-hop capability to the peer\n")
{
	int idx_peer = 1;
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (peer && peer->conf_if)
		return CMD_SUCCESS;

	return peer_flag_set_vty(vty, argv[idx_peer]->arg,
				 PEER_FLAG_CAPABILITY_ENHE);
}

DEFUN (no_neighbor_capability_enhe,
       no_neighbor_capability_enhe_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> capability extended-nexthop",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Advertise capability to the peer\n"
       "Advertise extended next-hop capability to the peer\n")
{
	int idx_peer = 2;
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (peer && peer->conf_if) {
		vty_out(vty,
			"Peer %s cannot have capability extended-nexthop turned off\n",
			argv[idx_peer]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	return peer_flag_unset_vty(vty, argv[idx_peer]->arg,
				   PEER_FLAG_CAPABILITY_ENHE);
}

/* neighbor capability software-version */
DEFPY(neighbor_capability_software_version,
      neighbor_capability_software_version_cmd,
      "[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor capability software-version",
      NO_STR
      NEIGHBOR_STR
      NEIGHBOR_ADDR_STR2
      "Advertise capability to the peer\n"
      "Advertise Software Version capability to the peer\n")
{
	struct peer *peer;
	int ret;

	peer = peer_and_group_lookup_vty(vty, neighbor);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	if (no)
		ret = peer_flag_unset_vty(vty, neighbor,
					  PEER_FLAG_CAPABILITY_SOFT_VERSION);
	else
		ret = peer_flag_set_vty(vty, neighbor,
					PEER_FLAG_CAPABILITY_SOFT_VERSION);

	bgp_capability_send(peer, AFI_IP, SAFI_UNICAST,
			    CAPABILITY_CODE_SOFT_VERSION,
			    no ? CAPABILITY_ACTION_UNSET
			       : CAPABILITY_ACTION_SET);

	return ret;
}

static int peer_af_flag_modify_vty(struct vty *vty, const char *peer_str,
				   afi_t afi, safi_t safi, uint64_t flag,
				   int set)
{
	int ret;
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, peer_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	if (set)
		ret = peer_af_flag_set(peer, afi, safi, flag);
	else
		ret = peer_af_flag_unset(peer, afi, safi, flag);

	return bgp_vty_return(vty, ret);
}

static int peer_af_flag_set_vty(struct vty *vty, const char *peer_str,
				afi_t afi, safi_t safi, uint64_t flag)
{
	return peer_af_flag_modify_vty(vty, peer_str, afi, safi, flag, 1);
}

static int peer_af_flag_unset_vty(struct vty *vty, const char *peer_str,
				  afi_t afi, safi_t safi, uint64_t flag)
{
	return peer_af_flag_modify_vty(vty, peer_str, afi, safi, flag, 0);
}

/* neighbor capability orf prefix-list. */
DEFUN (neighbor_capability_orf_prefix,
       neighbor_capability_orf_prefix_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> capability orf prefix-list <both|send|receive>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Advertise capability to the peer\n"
       "Advertise ORF capability to the peer\n"
       "Advertise prefixlist ORF capability to this neighbor\n"
       "Capability to SEND and RECEIVE the ORF to/from this neighbor\n"
       "Capability to RECEIVE the ORF from this neighbor\n"
       "Capability to SEND the ORF to this neighbor\n")
{
	int idx_send_recv = 5;
	char *peer_str = argv[1]->arg;
	struct peer *peer;
	afi_t afi = bgp_node_afi(vty);
	safi_t safi = bgp_node_safi(vty);
	int ret;

	peer = peer_and_group_lookup_vty(vty, peer_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	if (strmatch(argv[idx_send_recv]->text, "send")) {
		ret = peer_af_flag_set_vty(vty, peer_str, afi, safi,
					   PEER_FLAG_ORF_PREFIX_SM);
		bgp_capability_send(peer, afi, safi, CAPABILITY_CODE_ORF,
				    CAPABILITY_ACTION_SET);
		return ret;
	}

	if (strmatch(argv[idx_send_recv]->text, "receive")) {
		ret = peer_af_flag_set_vty(vty, peer_str, afi, safi,
					   PEER_FLAG_ORF_PREFIX_RM);
		bgp_capability_send(peer, afi, safi, CAPABILITY_CODE_ORF,
				    CAPABILITY_ACTION_SET);
		return ret;
	}

	if (strmatch(argv[idx_send_recv]->text, "both")) {
		ret = peer_af_flag_set_vty(vty, peer_str, afi, safi,
					   PEER_FLAG_ORF_PREFIX_SM) |
		      peer_af_flag_set_vty(vty, peer_str, afi, safi,
					   PEER_FLAG_ORF_PREFIX_RM);
		bgp_capability_send(peer, afi, safi, CAPABILITY_CODE_ORF,
				    CAPABILITY_ACTION_SET);
		return ret;
	}

	return CMD_WARNING_CONFIG_FAILED;
}

ALIAS_HIDDEN(
	neighbor_capability_orf_prefix,
	neighbor_capability_orf_prefix_hidden_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD> capability orf prefix-list <both|send|receive>",
	NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	"Advertise capability to the peer\n"
	"Advertise ORF capability to the peer\n"
	"Advertise prefixlist ORF capability to this neighbor\n"
	"Capability to SEND and RECEIVE the ORF to/from this neighbor\n"
	"Capability to RECEIVE the ORF from this neighbor\n"
	"Capability to SEND the ORF to this neighbor\n")

DEFUN (no_neighbor_capability_orf_prefix,
       no_neighbor_capability_orf_prefix_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> capability orf prefix-list <both|send|receive>",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Advertise capability to the peer\n"
       "Advertise ORF capability to the peer\n"
       "Advertise prefixlist ORF capability to this neighbor\n"
       "Capability to SEND and RECEIVE the ORF to/from this neighbor\n"
       "Capability to RECEIVE the ORF from this neighbor\n"
       "Capability to SEND the ORF to this neighbor\n")
{
	int idx_send_recv = 6;
	char *peer_str = argv[2]->arg;
	struct peer *peer;
	afi_t afi = bgp_node_afi(vty);
	safi_t safi = bgp_node_safi(vty);
	int ret;

	peer = peer_and_group_lookup_vty(vty, peer_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	if (strmatch(argv[idx_send_recv]->text, "send")) {
		ret = peer_af_flag_unset_vty(vty, peer_str, afi, safi,
					     PEER_FLAG_ORF_PREFIX_SM);
		bgp_capability_send(peer, afi, safi, CAPABILITY_CODE_ORF,
				    CAPABILITY_ACTION_UNSET);
		return ret;
	}

	if (strmatch(argv[idx_send_recv]->text, "receive")) {
		ret = peer_af_flag_unset_vty(vty, peer_str, afi, safi,
					     PEER_FLAG_ORF_PREFIX_RM);
		bgp_capability_send(peer, afi, safi, CAPABILITY_CODE_ORF,
				    CAPABILITY_ACTION_UNSET);
		return ret;
	}

	if (strmatch(argv[idx_send_recv]->text, "both")) {
		ret = peer_af_flag_unset_vty(vty, peer_str, afi, safi,
					     PEER_FLAG_ORF_PREFIX_SM) |
		      peer_af_flag_unset_vty(vty, peer_str, afi, safi,
					     PEER_FLAG_ORF_PREFIX_RM);
		bgp_capability_send(peer, afi, safi, CAPABILITY_CODE_ORF,
				    CAPABILITY_ACTION_UNSET);
		return ret;
	}

	return CMD_WARNING_CONFIG_FAILED;
}

ALIAS_HIDDEN(
	no_neighbor_capability_orf_prefix,
	no_neighbor_capability_orf_prefix_hidden_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD> capability orf prefix-list <both|send|receive>",
	NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	"Advertise capability to the peer\n"
	"Advertise ORF capability to the peer\n"
	"Advertise prefixlist ORF capability to this neighbor\n"
	"Capability to SEND and RECEIVE the ORF to/from this neighbor\n"
	"Capability to RECEIVE the ORF from this neighbor\n"
	"Capability to SEND the ORF to this neighbor\n")

/* neighbor next-hop-self. */
DEFUN (neighbor_nexthop_self,
       neighbor_nexthop_self_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> next-hop-self",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Disable the next hop calculation for this neighbor\n")
{
	int idx_peer = 1;
	return peer_af_flag_set_vty(vty, argv[idx_peer]->arg, bgp_node_afi(vty),
				    bgp_node_safi(vty), PEER_FLAG_NEXTHOP_SELF);
}

ALIAS_HIDDEN(neighbor_nexthop_self, neighbor_nexthop_self_hidden_cmd,
	     "neighbor <A.B.C.D|X:X::X:X|WORD> next-hop-self",
	     NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Disable the next hop calculation for this neighbor\n")

/* neighbor next-hop-self. */
DEFUN (neighbor_nexthop_self_force,
       neighbor_nexthop_self_force_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> next-hop-self force",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Disable the next hop calculation for this neighbor\n"
       "Set the next hop to self for reflected routes\n")
{
	int idx_peer = 1;
	return peer_af_flag_set_vty(vty, argv[idx_peer]->arg, bgp_node_afi(vty),
				    bgp_node_safi(vty),
				    PEER_FLAG_FORCE_NEXTHOP_SELF);
}

ALIAS_HIDDEN(neighbor_nexthop_self_force,
	     neighbor_nexthop_self_force_hidden_cmd,
	     "neighbor <A.B.C.D|X:X::X:X|WORD> next-hop-self force",
	     NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Disable the next hop calculation for this neighbor\n"
	     "Set the next hop to self for reflected routes\n")

ALIAS_HIDDEN(neighbor_nexthop_self_force,
	     neighbor_nexthop_self_all_hidden_cmd,
	     "neighbor <A.B.C.D|X:X::X:X|WORD> next-hop-self all",
	     NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Disable the next hop calculation for this neighbor\n"
	     "Set the next hop to self for reflected routes\n")

DEFUN (no_neighbor_nexthop_self,
       no_neighbor_nexthop_self_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> next-hop-self",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Disable the next hop calculation for this neighbor\n")
{
	int idx_peer = 2;
	return peer_af_flag_unset_vty(vty, argv[idx_peer]->arg,
				      bgp_node_afi(vty), bgp_node_safi(vty),
				      PEER_FLAG_NEXTHOP_SELF);
}

ALIAS_HIDDEN(no_neighbor_nexthop_self, no_neighbor_nexthop_self_hidden_cmd,
	     "no neighbor <A.B.C.D|X:X::X:X|WORD> next-hop-self",
	     NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Disable the next hop calculation for this neighbor\n")

DEFUN (no_neighbor_nexthop_self_force,
       no_neighbor_nexthop_self_force_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> next-hop-self force",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Disable the next hop calculation for this neighbor\n"
       "Set the next hop to self for reflected routes\n")
{
	int idx_peer = 2;
	return peer_af_flag_unset_vty(vty, argv[idx_peer]->arg,
				      bgp_node_afi(vty), bgp_node_safi(vty),
				      PEER_FLAG_FORCE_NEXTHOP_SELF);
}

ALIAS_HIDDEN(no_neighbor_nexthop_self_force,
	     no_neighbor_nexthop_self_force_hidden_cmd,
	     "no neighbor <A.B.C.D|X:X::X:X|WORD> next-hop-self force",
	     NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Disable the next hop calculation for this neighbor\n"
	     "Set the next hop to self for reflected routes\n")

ALIAS_HIDDEN(no_neighbor_nexthop_self_force,
	     no_neighbor_nexthop_self_all_hidden_cmd,
	     "no neighbor <A.B.C.D|X:X::X:X|WORD> next-hop-self all",
	     NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Disable the next hop calculation for this neighbor\n"
	     "Set the next hop to self for reflected routes\n")

/* neighbor as-override */
DEFUN (neighbor_as_override,
       neighbor_as_override_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> as-override",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Override ASNs in outbound updates if aspath equals remote-as\n")
{
	int idx_peer = 1;
	return peer_af_flag_set_vty(vty, argv[idx_peer]->arg, bgp_node_afi(vty),
				    bgp_node_safi(vty), PEER_FLAG_AS_OVERRIDE);
}

ALIAS_HIDDEN(neighbor_as_override, neighbor_as_override_hidden_cmd,
	     "neighbor <A.B.C.D|X:X::X:X|WORD> as-override",
	     NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Override ASNs in outbound updates if aspath equals remote-as\n")

DEFUN (no_neighbor_as_override,
       no_neighbor_as_override_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> as-override",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Override ASNs in outbound updates if aspath equals remote-as\n")
{
	int idx_peer = 2;
	return peer_af_flag_unset_vty(vty, argv[idx_peer]->arg,
				      bgp_node_afi(vty), bgp_node_safi(vty),
				      PEER_FLAG_AS_OVERRIDE);
}

ALIAS_HIDDEN(no_neighbor_as_override, no_neighbor_as_override_hidden_cmd,
	     "no neighbor <A.B.C.D|X:X::X:X|WORD> as-override",
	     NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Override ASNs in outbound updates if aspath equals remote-as\n")

/* neighbor remove-private-AS. */
DEFUN (neighbor_remove_private_as,
       neighbor_remove_private_as_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> remove-private-AS",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Remove private ASNs in outbound updates\n")
{
	int idx_peer = 1;
	return peer_af_flag_set_vty(vty, argv[idx_peer]->arg, bgp_node_afi(vty),
				    bgp_node_safi(vty),
				    PEER_FLAG_REMOVE_PRIVATE_AS);
}

ALIAS_HIDDEN(neighbor_remove_private_as, neighbor_remove_private_as_hidden_cmd,
	     "neighbor <A.B.C.D|X:X::X:X|WORD> remove-private-AS",
	     NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Remove private ASNs in outbound updates\n")

DEFUN (neighbor_remove_private_as_all,
       neighbor_remove_private_as_all_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> remove-private-AS all",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Remove private ASNs in outbound updates\n"
       "Apply to all AS numbers\n")
{
	int idx_peer = 1;
	return peer_af_flag_set_vty(vty, argv[idx_peer]->arg, bgp_node_afi(vty),
				    bgp_node_safi(vty),
				    PEER_FLAG_REMOVE_PRIVATE_AS_ALL);
}

ALIAS_HIDDEN(neighbor_remove_private_as_all,
	     neighbor_remove_private_as_all_hidden_cmd,
	     "neighbor <A.B.C.D|X:X::X:X|WORD> remove-private-AS all",
	     NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Remove private ASNs in outbound updates\n"
	     "Apply to all AS numbers\n")

DEFUN (neighbor_remove_private_as_replace_as,
       neighbor_remove_private_as_replace_as_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> remove-private-AS replace-AS",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Remove private ASNs in outbound updates\n"
       "Replace private ASNs with our ASN in outbound updates\n")
{
	int idx_peer = 1;
	return peer_af_flag_set_vty(vty, argv[idx_peer]->arg, bgp_node_afi(vty),
				    bgp_node_safi(vty),
				    PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE);
}

ALIAS_HIDDEN(neighbor_remove_private_as_replace_as,
	     neighbor_remove_private_as_replace_as_hidden_cmd,
	     "neighbor <A.B.C.D|X:X::X:X|WORD> remove-private-AS replace-AS",
	     NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Remove private ASNs in outbound updates\n"
	     "Replace private ASNs with our ASN in outbound updates\n")

DEFUN (neighbor_remove_private_as_all_replace_as,
       neighbor_remove_private_as_all_replace_as_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> remove-private-AS all replace-AS",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Remove private ASNs in outbound updates\n"
       "Apply to all AS numbers\n"
       "Replace private ASNs with our ASN in outbound updates\n")
{
	int idx_peer = 1;
	return peer_af_flag_set_vty(vty, argv[idx_peer]->arg, bgp_node_afi(vty),
				    bgp_node_safi(vty),
				    PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE);
}

ALIAS_HIDDEN(
	neighbor_remove_private_as_all_replace_as,
	neighbor_remove_private_as_all_replace_as_hidden_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD> remove-private-AS all replace-AS",
	NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	"Remove private ASNs in outbound updates\n"
	"Apply to all AS numbers\n"
	"Replace private ASNs with our ASN in outbound updates\n")

DEFUN (no_neighbor_remove_private_as,
       no_neighbor_remove_private_as_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> remove-private-AS",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Remove private ASNs in outbound updates\n")
{
	int idx_peer = 2;
	return peer_af_flag_unset_vty(vty, argv[idx_peer]->arg,
				      bgp_node_afi(vty), bgp_node_safi(vty),
				      PEER_FLAG_REMOVE_PRIVATE_AS);
}

ALIAS_HIDDEN(no_neighbor_remove_private_as,
	     no_neighbor_remove_private_as_hidden_cmd,
	     "no neighbor <A.B.C.D|X:X::X:X|WORD> remove-private-AS",
	     NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Remove private ASNs in outbound updates\n")

DEFUN (no_neighbor_remove_private_as_all,
       no_neighbor_remove_private_as_all_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> remove-private-AS all",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Remove private ASNs in outbound updates\n"
       "Apply to all AS numbers\n")
{
	int idx_peer = 2;
	return peer_af_flag_unset_vty(vty, argv[idx_peer]->arg,
				      bgp_node_afi(vty), bgp_node_safi(vty),
				      PEER_FLAG_REMOVE_PRIVATE_AS_ALL);
}

ALIAS_HIDDEN(no_neighbor_remove_private_as_all,
	     no_neighbor_remove_private_as_all_hidden_cmd,
	     "no neighbor <A.B.C.D|X:X::X:X|WORD> remove-private-AS all",
	     NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Remove private ASNs in outbound updates\n"
	     "Apply to all AS numbers\n")

DEFUN (no_neighbor_remove_private_as_replace_as,
       no_neighbor_remove_private_as_replace_as_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> remove-private-AS replace-AS",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Remove private ASNs in outbound updates\n"
       "Replace private ASNs with our ASN in outbound updates\n")
{
	int idx_peer = 2;
	return peer_af_flag_unset_vty(vty, argv[idx_peer]->arg,
				      bgp_node_afi(vty), bgp_node_safi(vty),
				      PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE);
}

ALIAS_HIDDEN(no_neighbor_remove_private_as_replace_as,
	     no_neighbor_remove_private_as_replace_as_hidden_cmd,
	     "no neighbor <A.B.C.D|X:X::X:X|WORD> remove-private-AS replace-AS",
	     NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Remove private ASNs in outbound updates\n"
	     "Replace private ASNs with our ASN in outbound updates\n")

DEFUN (no_neighbor_remove_private_as_all_replace_as,
       no_neighbor_remove_private_as_all_replace_as_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> remove-private-AS all replace-AS",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Remove private ASNs in outbound updates\n"
       "Apply to all AS numbers\n"
       "Replace private ASNs with our ASN in outbound updates\n")
{
	int idx_peer = 2;
	return peer_af_flag_unset_vty(vty, argv[idx_peer]->arg,
				      bgp_node_afi(vty), bgp_node_safi(vty),
				      PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE);
}

ALIAS_HIDDEN(
	no_neighbor_remove_private_as_all_replace_as,
	no_neighbor_remove_private_as_all_replace_as_hidden_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD> remove-private-AS all replace-AS",
	NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	"Remove private ASNs in outbound updates\n"
	"Apply to all AS numbers\n"
	"Replace private ASNs with our ASN in outbound updates\n")


/* neighbor send-community. */
DEFUN (neighbor_send_community,
       neighbor_send_community_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> send-community",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Send Community attribute to this neighbor\n")
{
	int idx_peer = 1;

	return peer_af_flag_set_vty(vty, argv[idx_peer]->arg, bgp_node_afi(vty),
				    bgp_node_safi(vty),
				    PEER_FLAG_SEND_COMMUNITY);
}

ALIAS_HIDDEN(neighbor_send_community, neighbor_send_community_hidden_cmd,
	     "neighbor <A.B.C.D|X:X::X:X|WORD> send-community",
	     NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Send Community attribute to this neighbor\n")

DEFUN (no_neighbor_send_community,
       no_neighbor_send_community_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> send-community",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Send Community attribute to this neighbor\n")
{
	int idx_peer = 2;

	return peer_af_flag_unset_vty(vty, argv[idx_peer]->arg,
				      bgp_node_afi(vty), bgp_node_safi(vty),
				      PEER_FLAG_SEND_COMMUNITY);
}

ALIAS_HIDDEN(no_neighbor_send_community, no_neighbor_send_community_hidden_cmd,
	     "no neighbor <A.B.C.D|X:X::X:X|WORD> send-community",
	     NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Send Community attribute to this neighbor\n")

/* neighbor send-community extended. */
DEFUN (neighbor_send_community_type,
       neighbor_send_community_type_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> send-community <both|all|extended|standard|large>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Send Community attribute to this neighbor\n"
       "Send Standard and Extended Community attributes\n"
       "Send Standard, Large and Extended Community attributes\n"
       "Send Extended Community attributes\n"
       "Send Standard Community attributes\n"
       "Send Large Community attributes\n")
{
	const char *type = argv[argc - 1]->text;
	char *peer_str = argv[1]->arg;
	struct peer *peer;
	afi_t afi = bgp_node_afi(vty);
	safi_t safi = bgp_node_safi(vty);

	peer = peer_and_group_lookup_vty(vty, peer_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	if (strmatch(type, "standard"))
		return peer_af_flag_set_vty(vty, peer_str, afi, safi,
					    PEER_FLAG_SEND_COMMUNITY);

	if (strmatch(type, "extended"))
		return peer_af_flag_set_vty(vty, peer_str, afi, safi,
					    PEER_FLAG_SEND_EXT_COMMUNITY);

	if (strmatch(type, "large"))
		return peer_af_flag_set_vty(vty, peer_str, afi, safi,
					    PEER_FLAG_SEND_LARGE_COMMUNITY);

	if (strmatch(type, "both")) {
		return peer_af_flag_set_vty(vty, peer_str, afi, safi,
					    PEER_FLAG_SEND_COMMUNITY)
		       | peer_af_flag_set_vty(vty, peer_str, afi, safi,
					      PEER_FLAG_SEND_EXT_COMMUNITY);
	}
	return peer_af_flag_set_vty(vty, peer_str, afi, safi,
				    PEER_FLAG_SEND_COMMUNITY)
	       | peer_af_flag_set_vty(vty, peer_str, afi, safi,
				      PEER_FLAG_SEND_EXT_COMMUNITY)
	       | peer_af_flag_set_vty(vty, peer_str, afi, safi,
				      PEER_FLAG_SEND_LARGE_COMMUNITY);
}

ALIAS_HIDDEN(
	neighbor_send_community_type, neighbor_send_community_type_hidden_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD> send-community <both|all|extended|standard|large>",
	NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	"Send Community attribute to this neighbor\n"
	"Send Standard and Extended Community attributes\n"
	"Send Standard, Large and Extended Community attributes\n"
	"Send Extended Community attributes\n"
	"Send Standard Community attributes\n"
	"Send Large Community attributes\n")

DEFUN (no_neighbor_send_community_type,
       no_neighbor_send_community_type_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> send-community <both|all|extended|standard|large>",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Send Community attribute to this neighbor\n"
       "Send Standard and Extended Community attributes\n"
       "Send Standard, Large and Extended Community attributes\n"
       "Send Extended Community attributes\n"
       "Send Standard Community attributes\n"
       "Send Large Community attributes\n")
{
	const char *type = argv[argc - 1]->text;
	char *peer_str = argv[2]->arg;
	struct peer *peer;
	afi_t afi = bgp_node_afi(vty);
	safi_t safi = bgp_node_safi(vty);

	peer = peer_and_group_lookup_vty(vty, peer_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	if (strmatch(type, "standard"))
		return peer_af_flag_unset_vty(vty, peer_str, afi, safi,
					      PEER_FLAG_SEND_COMMUNITY);

	if (strmatch(type, "extended"))
		return peer_af_flag_unset_vty(vty, peer_str, afi, safi,
					      PEER_FLAG_SEND_EXT_COMMUNITY);

	if (strmatch(type, "large"))
		return peer_af_flag_unset_vty(vty, peer_str, afi, safi,
					      PEER_FLAG_SEND_LARGE_COMMUNITY);

	if (strmatch(type, "both")) {

		return peer_af_flag_unset_vty(vty, peer_str, afi, safi,
					      PEER_FLAG_SEND_COMMUNITY)
		       | peer_af_flag_unset_vty(vty, peer_str, afi, safi,
						PEER_FLAG_SEND_EXT_COMMUNITY);
	}

	return peer_af_flag_unset_vty(vty, peer_str, afi, safi,
				      PEER_FLAG_SEND_COMMUNITY)
	       | peer_af_flag_unset_vty(vty, peer_str, afi, safi,
					PEER_FLAG_SEND_EXT_COMMUNITY)
	       | peer_af_flag_unset_vty(vty, peer_str, afi, safi,
					PEER_FLAG_SEND_LARGE_COMMUNITY);
}

ALIAS_HIDDEN(
	no_neighbor_send_community_type,
	no_neighbor_send_community_type_hidden_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD> send-community <both|all|extended|standard|large>",
	NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	"Send Community attribute to this neighbor\n"
	"Send Standard and Extended Community attributes\n"
	"Send Standard, Large and Extended Community attributes\n"
	"Send Extended Community attributes\n"
	"Send Standard Community attributes\n"
	"Send Large Community attributes\n")

DEFPY (neighbor_ecommunity_rpki,
       neighbor_ecommunity_rpki_cmd,
       "[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor send-community extended rpki",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Send Community attribute to this neighbor\n"
       "Send Extended Community attributes\n"
       "Send RPKI Extended Community attributes\n")
{
	struct peer *peer;
	afi_t afi = bgp_node_afi(vty);
	safi_t safi = bgp_node_safi(vty);

	peer = peer_and_group_lookup_vty(vty, neighbor);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	if (no)
		return peer_af_flag_unset_vty(vty, neighbor, afi, safi,
					      PEER_FLAG_SEND_EXT_COMMUNITY_RPKI);
	else
		return peer_af_flag_set_vty(vty, neighbor, afi, safi,
					    PEER_FLAG_SEND_EXT_COMMUNITY_RPKI);
}

/* neighbor soft-reconfig. */
DEFUN (neighbor_soft_reconfiguration,
       neighbor_soft_reconfiguration_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> soft-reconfiguration inbound",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Per neighbor soft reconfiguration\n"
       "Allow inbound soft reconfiguration for this neighbor\n")
{
	int idx_peer = 1;
	return peer_af_flag_set_vty(vty, argv[idx_peer]->arg, bgp_node_afi(vty),
				    bgp_node_safi(vty),
				    PEER_FLAG_SOFT_RECONFIG);
}

ALIAS_HIDDEN(neighbor_soft_reconfiguration,
	     neighbor_soft_reconfiguration_hidden_cmd,
	     "neighbor <A.B.C.D|X:X::X:X|WORD> soft-reconfiguration inbound",
	     NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Per neighbor soft reconfiguration\n"
	     "Allow inbound soft reconfiguration for this neighbor\n")

DEFUN (no_neighbor_soft_reconfiguration,
       no_neighbor_soft_reconfiguration_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> soft-reconfiguration inbound",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Per neighbor soft reconfiguration\n"
       "Allow inbound soft reconfiguration for this neighbor\n")
{
	int idx_peer = 2;
	return peer_af_flag_unset_vty(vty, argv[idx_peer]->arg,
				      bgp_node_afi(vty), bgp_node_safi(vty),
				      PEER_FLAG_SOFT_RECONFIG);
}

ALIAS_HIDDEN(no_neighbor_soft_reconfiguration,
	     no_neighbor_soft_reconfiguration_hidden_cmd,
	     "no neighbor <A.B.C.D|X:X::X:X|WORD> soft-reconfiguration inbound",
	     NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Per neighbor soft reconfiguration\n"
	     "Allow inbound soft reconfiguration for this neighbor\n")

DEFUN (neighbor_route_reflector_client,
       neighbor_route_reflector_client_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> route-reflector-client",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Configure a neighbor as Route Reflector client\n")
{
	int idx_peer = 1;
	struct peer *peer;


	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	return peer_af_flag_set_vty(vty, argv[idx_peer]->arg, bgp_node_afi(vty),
				    bgp_node_safi(vty),
				    PEER_FLAG_REFLECTOR_CLIENT);
}

ALIAS_HIDDEN(neighbor_route_reflector_client,
	     neighbor_route_reflector_client_hidden_cmd,
	     "neighbor <A.B.C.D|X:X::X:X|WORD> route-reflector-client",
	     NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Configure a neighbor as Route Reflector client\n")

DEFUN (no_neighbor_route_reflector_client,
       no_neighbor_route_reflector_client_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> route-reflector-client",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Configure a neighbor as Route Reflector client\n")
{
	int idx_peer = 2;
	return peer_af_flag_unset_vty(vty, argv[idx_peer]->arg,
				      bgp_node_afi(vty), bgp_node_safi(vty),
				      PEER_FLAG_REFLECTOR_CLIENT);
}

ALIAS_HIDDEN(no_neighbor_route_reflector_client,
	     no_neighbor_route_reflector_client_hidden_cmd,
	     "no neighbor <A.B.C.D|X:X::X:X|WORD> route-reflector-client",
	     NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Configure a neighbor as Route Reflector client\n")

/* neighbor route-server-client. */
DEFUN (neighbor_route_server_client,
       neighbor_route_server_client_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> route-server-client",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Configure a neighbor as Route Server client\n")
{
	int idx_peer = 1;
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;
	return peer_af_flag_set_vty(vty, argv[idx_peer]->arg, bgp_node_afi(vty),
				    bgp_node_safi(vty),
				    PEER_FLAG_RSERVER_CLIENT);
}

ALIAS_HIDDEN(neighbor_route_server_client,
	     neighbor_route_server_client_hidden_cmd,
	     "neighbor <A.B.C.D|X:X::X:X|WORD> route-server-client",
	     NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Configure a neighbor as Route Server client\n")

DEFUN (no_neighbor_route_server_client,
       no_neighbor_route_server_client_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> route-server-client",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Configure a neighbor as Route Server client\n")
{
	int idx_peer = 2;
	return peer_af_flag_unset_vty(vty, argv[idx_peer]->arg,
				      bgp_node_afi(vty), bgp_node_safi(vty),
				      PEER_FLAG_RSERVER_CLIENT);
}

ALIAS_HIDDEN(no_neighbor_route_server_client,
	     no_neighbor_route_server_client_hidden_cmd,
	     "no neighbor <A.B.C.D|X:X::X:X|WORD> route-server-client",
	     NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Configure a neighbor as Route Server client\n")

DEFUN (neighbor_nexthop_local_unchanged,
       neighbor_nexthop_local_unchanged_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> nexthop-local unchanged",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Configure treatment of outgoing link-local nexthop attribute\n"
       "Leave link-local nexthop unchanged for this peer\n")
{
	int idx_peer = 1;
	return peer_af_flag_set_vty(vty, argv[idx_peer]->arg, bgp_node_afi(vty),
				    bgp_node_safi(vty),
				    PEER_FLAG_NEXTHOP_LOCAL_UNCHANGED);
}

DEFUN (no_neighbor_nexthop_local_unchanged,
       no_neighbor_nexthop_local_unchanged_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> nexthop-local unchanged",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Configure treatment of outgoing link-local-nexthop attribute\n"
       "Leave link-local nexthop unchanged for this peer\n")
{
	int idx_peer = 2;
	return peer_af_flag_unset_vty(vty, argv[idx_peer]->arg,
				      bgp_node_afi(vty), bgp_node_safi(vty),
				      PEER_FLAG_NEXTHOP_LOCAL_UNCHANGED);
}

DEFUN (neighbor_attr_unchanged,
       neighbor_attr_unchanged_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> attribute-unchanged [{as-path|next-hop|med}]",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "As-path attribute\n"
       "Nexthop attribute\n"
       "Med attribute\n")
{
	int idx = 0;
	char *peer_str = argv[1]->arg;
	struct peer *peer;
	bool aspath = false;
	bool nexthop = false;
	bool med = false;
	afi_t afi = bgp_node_afi(vty);
	safi_t safi = bgp_node_safi(vty);
	int ret = 0;

	peer = peer_and_group_lookup_vty(vty, peer_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	if (argv_find(argv, argc, "as-path", &idx))
		aspath = true;

	idx = 0;
	if (argv_find(argv, argc, "next-hop", &idx))
		nexthop = true;

	idx = 0;
	if (argv_find(argv, argc, "med", &idx))
		med = true;

	/* no flags means all of them! */
	if (!aspath && !nexthop && !med) {
		ret = peer_af_flag_set_vty(vty, peer_str, afi, safi,
					   PEER_FLAG_AS_PATH_UNCHANGED);
		ret |= peer_af_flag_set_vty(vty, peer_str, afi, safi,
					    PEER_FLAG_NEXTHOP_UNCHANGED);
		ret |= peer_af_flag_set_vty(vty, peer_str, afi, safi,
					    PEER_FLAG_MED_UNCHANGED);
	} else {
		if (!aspath) {
			if (peer_af_flag_check(peer, afi, safi,
					       PEER_FLAG_AS_PATH_UNCHANGED)) {
				ret |= peer_af_flag_unset_vty(
					vty, peer_str, afi, safi,
					PEER_FLAG_AS_PATH_UNCHANGED);
			}
		} else
			ret |= peer_af_flag_set_vty(
				vty, peer_str, afi, safi,
				PEER_FLAG_AS_PATH_UNCHANGED);

		if (!nexthop) {
			if (peer_af_flag_check(peer, afi, safi,
					       PEER_FLAG_NEXTHOP_UNCHANGED)) {
				ret |= peer_af_flag_unset_vty(
					vty, peer_str, afi, safi,
					PEER_FLAG_NEXTHOP_UNCHANGED);
			}
		} else
			ret |= peer_af_flag_set_vty(
				vty, peer_str, afi, safi,
				PEER_FLAG_NEXTHOP_UNCHANGED);

		if (!med) {
			if (peer_af_flag_check(peer, afi, safi,
					       PEER_FLAG_MED_UNCHANGED)) {
				ret |= peer_af_flag_unset_vty(
					vty, peer_str, afi, safi,
					PEER_FLAG_MED_UNCHANGED);
			}
		} else
			ret |= peer_af_flag_set_vty(vty, peer_str, afi, safi,
						    PEER_FLAG_MED_UNCHANGED);
	}

	return ret;
}

ALIAS_HIDDEN(
	neighbor_attr_unchanged, neighbor_attr_unchanged_hidden_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD> attribute-unchanged [{as-path|next-hop|med}]",
	NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	"BGP attribute is propagated unchanged to this neighbor\n"
	"As-path attribute\n"
	"Nexthop attribute\n"
	"Med attribute\n")

DEFUN (no_neighbor_attr_unchanged,
       no_neighbor_attr_unchanged_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> attribute-unchanged [{as-path|next-hop|med}]",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "As-path attribute\n"
       "Nexthop attribute\n"
       "Med attribute\n")
{
	int idx = 0;
	char *peer_str = argv[2]->arg;
	struct peer *peer;
	bool aspath = false;
	bool nexthop = false;
	bool med = false;
	afi_t afi = bgp_node_afi(vty);
	safi_t safi = bgp_node_safi(vty);
	int ret = 0;

	peer = peer_and_group_lookup_vty(vty, peer_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	if (argv_find(argv, argc, "as-path", &idx))
		aspath = true;

	idx = 0;
	if (argv_find(argv, argc, "next-hop", &idx))
		nexthop = true;

	idx = 0;
	if (argv_find(argv, argc, "med", &idx))
		med = true;

	if (!aspath && !nexthop && !med) // no flags means all of them!
		return peer_af_flag_unset_vty(vty, peer_str, afi, safi,
					      PEER_FLAG_AS_PATH_UNCHANGED)
		       | peer_af_flag_unset_vty(vty, peer_str, afi, safi,
						PEER_FLAG_NEXTHOP_UNCHANGED)
		       | peer_af_flag_unset_vty(vty, peer_str, afi, safi,
						PEER_FLAG_MED_UNCHANGED);

	if (aspath)
		ret |= peer_af_flag_unset_vty(vty, peer_str, afi, safi,
					      PEER_FLAG_AS_PATH_UNCHANGED);

	if (nexthop)
		ret |= peer_af_flag_unset_vty(vty, peer_str, afi, safi,
					      PEER_FLAG_NEXTHOP_UNCHANGED);

	if (med)
		ret |= peer_af_flag_unset_vty(vty, peer_str, afi, safi,
					      PEER_FLAG_MED_UNCHANGED);

	return ret;
}

ALIAS_HIDDEN(
	no_neighbor_attr_unchanged, no_neighbor_attr_unchanged_hidden_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD> attribute-unchanged [{as-path|next-hop|med}]",
	NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	"BGP attribute is propagated unchanged to this neighbor\n"
	"As-path attribute\n"
	"Nexthop attribute\n"
	"Med attribute\n")

/* EBGP multihop configuration. */
static int peer_ebgp_multihop_set_vty(struct vty *vty, const char *ip_str,
				      const char *ttl_str)
{
	struct peer *peer;
	unsigned int ttl;

	peer = peer_and_group_lookup_vty(vty, ip_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	if (peer->conf_if)
		return bgp_vty_return(vty, BGP_ERR_INVALID_FOR_DIRECT_PEER);

	if (!ttl_str)
		ttl = MAXTTL;
	else
		ttl = strtoul(ttl_str, NULL, 10);

	return bgp_vty_return(vty, peer_ebgp_multihop_set(peer, ttl));
}

static int peer_ebgp_multihop_unset_vty(struct vty *vty, const char *ip_str)
{
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, ip_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	return bgp_vty_return(vty, peer_ebgp_multihop_unset(peer));
}

/* neighbor ebgp-multihop. */
DEFUN (neighbor_ebgp_multihop,
       neighbor_ebgp_multihop_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> ebgp-multihop",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Allow EBGP neighbors not on directly connected networks\n")
{
	int idx_peer = 1;
	return peer_ebgp_multihop_set_vty(vty, argv[idx_peer]->arg, NULL);
}

DEFUN (neighbor_ebgp_multihop_ttl,
       neighbor_ebgp_multihop_ttl_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> ebgp-multihop (1-255)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Allow EBGP neighbors not on directly connected networks\n"
       "maximum hop count\n")
{
	int idx_peer = 1;
	int idx_number = 3;
	return peer_ebgp_multihop_set_vty(vty, argv[idx_peer]->arg,
					  argv[idx_number]->arg);
}

DEFUN (no_neighbor_ebgp_multihop,
       no_neighbor_ebgp_multihop_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> ebgp-multihop [(1-255)]",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Allow EBGP neighbors not on directly connected networks\n"
       "maximum hop count\n")
{
	int idx_peer = 2;
	return peer_ebgp_multihop_unset_vty(vty, argv[idx_peer]->arg);
}

DEFPY (neighbor_aigp,
       neighbor_aigp_cmd,
       "[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor aigp",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Enable send and receive of the AIGP attribute per neighbor\n")
{
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, neighbor);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	if (no)
		return peer_flag_unset_vty(vty, neighbor, PEER_FLAG_AIGP);
	else
		return peer_flag_set_vty(vty, neighbor, PEER_FLAG_AIGP);
}

static uint8_t get_role_by_name(const char *role_str)
{
	if (strncmp(role_str, "peer", 2) == 0)
		return ROLE_PEER;
	if (strncmp(role_str, "provider", 2) == 0)
		return ROLE_PROVIDER;
	if (strncmp(role_str, "customer", 2) == 0)
		return ROLE_CUSTOMER;
	if (strncmp(role_str, "rs-server", 4) == 0)
		return ROLE_RS_SERVER;
	if (strncmp(role_str, "rs-client", 4) == 0)
		return ROLE_RS_CLIENT;
	return ROLE_UNDEFINED;
}

static int peer_role_set_vty(struct vty *vty, struct peer *peer,
			     const char *role_str, bool strict_mode)
{
	uint8_t role = get_role_by_name(role_str);

	if (role == ROLE_UNDEFINED)
		return bgp_vty_return(vty, BGP_ERR_INVALID_ROLE_NAME);
	return bgp_vty_return(vty, peer_role_set(peer, role, strict_mode));
}

DEFPY(neighbor_role,
      neighbor_role_cmd,
      "neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor local-role <provider|rs-server|rs-client|customer|peer>$role",
      NEIGHBOR_STR
      NEIGHBOR_ADDR_STR2
      "Set session role\n"
      ROLE_STR)
{
	int ret;
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, neighbor);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	ret = peer_role_set_vty(vty, peer, role, false);

	bgp_capability_send(peer, AFI_IP, SAFI_UNICAST, CAPABILITY_CODE_ROLE,
			    CAPABILITY_ACTION_SET);

	return ret;
}

DEFPY(neighbor_role_strict,
      neighbor_role_strict_cmd,
      "neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor local-role <provider|rs-server|rs-client|customer|peer>$role strict-mode",
      NEIGHBOR_STR
      NEIGHBOR_ADDR_STR2
      "Set session role\n"
      ROLE_STR
      "Use additional restriction on peer\n")
{
	int ret;
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, neighbor);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	ret = peer_role_set_vty(vty, peer, role, true);

	bgp_capability_send(peer, AFI_IP, SAFI_UNICAST, CAPABILITY_CODE_ROLE,
			    CAPABILITY_ACTION_SET);

	return ret;
}

DEFPY(no_neighbor_role,
      no_neighbor_role_cmd,
      "no neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor local-role <provider|rs-server|rs-client|customer|peer> [strict-mode]",
      NO_STR
      NEIGHBOR_STR
      NEIGHBOR_ADDR_STR2
      "Set session role\n"
      ROLE_STR
      "Use additional restriction on peer\n")
{
	int ret;
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, neighbor);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	ret = bgp_vty_return(vty, peer_role_unset(peer));

	bgp_capability_send(peer, AFI_IP, SAFI_UNICAST, CAPABILITY_CODE_ROLE,
			    CAPABILITY_ACTION_UNSET);

	return ret;
}

DEFPY (neighbor_oad,
       neighbor_oad_cmd,
       "[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor oad",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Set peering session type to EBGP-OAD\n")
{
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, neighbor);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	if (no)
		peer->sub_sort = 0;
	else if (peer->sort == BGP_PEER_EBGP)
		peer->sub_sort = BGP_PEER_EBGP_OAD;

	return CMD_SUCCESS;
}

/* disable-connected-check */
DEFUN (neighbor_disable_connected_check,
       neighbor_disable_connected_check_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> <disable-connected-check|enforce-multihop>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "one-hop away EBGP peer using loopback address\n"
       "Enforce EBGP neighbors perform multihop\n")
{
	int idx_peer = 1;
	return peer_flag_set_vty(vty, argv[idx_peer]->arg,
				 PEER_FLAG_DISABLE_CONNECTED_CHECK);
}

DEFUN (no_neighbor_disable_connected_check,
       no_neighbor_disable_connected_check_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> <disable-connected-check|enforce-multihop>",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "one-hop away EBGP peer using loopback address\n"
       "Enforce EBGP neighbors perform multihop\n")
{
	int idx_peer = 2;
	return peer_flag_unset_vty(vty, argv[idx_peer]->arg,
				   PEER_FLAG_DISABLE_CONNECTED_CHECK);
}

DEFPY(neighbor_extended_link_bw,
      neighbor_extended_link_bw_cmd,
      "[no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor extended-link-bandwidth",
      NO_STR
      NEIGHBOR_STR
      NEIGHBOR_ADDR_STR2
      "Send Extended (64-bit) version of encoding for Link-Bandwidth\n")
{
	int ret;

	if (no)
		ret = peer_flag_unset_vty(vty, neighbor,
					  PEER_FLAG_EXTENDED_LINK_BANDWIDTH);
	else
		ret = peer_flag_set_vty(vty, neighbor,
					PEER_FLAG_EXTENDED_LINK_BANDWIDTH);

	return ret;
}

/* disable-link-bw-encoding-ieee */
DEFUN(neighbor_disable_link_bw_encoding_ieee,
      neighbor_disable_link_bw_encoding_ieee_cmd,
      "neighbor <A.B.C.D|X:X::X:X|WORD> disable-link-bw-encoding-ieee",
      NEIGHBOR_STR NEIGHBOR_ADDR_STR2
      "Disable IEEE floating-point encoding for extended community bandwidth\n")
{
	int idx_peer = 1;

	return peer_flag_set_vty(vty, argv[idx_peer]->arg,
				 PEER_FLAG_DISABLE_LINK_BW_ENCODING_IEEE);
}

DEFUN(no_neighbor_disable_link_bw_encoding_ieee,
      no_neighbor_disable_link_bw_encoding_ieee_cmd,
      "no neighbor <A.B.C.D|X:X::X:X|WORD> disable-link-bw-encoding-ieee",
      NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
      "Disable IEEE floating-point encoding for extended community bandwidth\n")
{
	int idx_peer = 2;

	return peer_flag_unset_vty(vty, argv[idx_peer]->arg,
				   PEER_FLAG_DISABLE_LINK_BW_ENCODING_IEEE);
}

/* extended-optional-parameters */
DEFUN(neighbor_extended_optional_parameters,
      neighbor_extended_optional_parameters_cmd,
      "neighbor <A.B.C.D|X:X::X:X|WORD> extended-optional-parameters",
      NEIGHBOR_STR NEIGHBOR_ADDR_STR2
      "Force the extended optional parameters format for OPEN messages\n")
{
	int idx_peer = 1;

	return peer_flag_set_vty(vty, argv[idx_peer]->arg,
				 PEER_FLAG_EXTENDED_OPT_PARAMS);
}

DEFUN(no_neighbor_extended_optional_parameters,
      no_neighbor_extended_optional_parameters_cmd,
      "no neighbor <A.B.C.D|X:X::X:X|WORD> extended-optional-parameters",
      NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
      "Force the extended optional parameters format for OPEN messages\n")
{
	int idx_peer = 2;

	return peer_flag_unset_vty(vty, argv[idx_peer]->arg,
				   PEER_FLAG_EXTENDED_OPT_PARAMS);
}

/* enforce-first-as */
DEFUN (neighbor_enforce_first_as,
       neighbor_enforce_first_as_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> enforce-first-as",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Enforce the first AS for EBGP routes\n")
{
	int idx_peer = 1;

	return peer_flag_set_vty(vty, argv[idx_peer]->arg,
				 PEER_FLAG_ENFORCE_FIRST_AS);
}

DEFUN (no_neighbor_enforce_first_as,
       no_neighbor_enforce_first_as_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> enforce-first-as",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Enforce the first AS for EBGP routes\n")
{
	int idx_peer = 2;

	return peer_flag_unset_vty(vty, argv[idx_peer]->arg,
				   PEER_FLAG_ENFORCE_FIRST_AS);
}


DEFUN (neighbor_description,
       neighbor_description_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> description LINE...",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Neighbor specific description\n"
       "Up to 80 characters describing this neighbor\n")
{
	int idx_peer = 1;
	int idx_line = 3;
	struct peer *peer;
	char *str;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	str = argv_concat(argv, argc, idx_line);

	peer_description_set(peer, str);

	XFREE(MTYPE_TMP, str);

	return CMD_SUCCESS;
}

DEFUN (no_neighbor_description,
       no_neighbor_description_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> description",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Neighbor specific description\n")
{
	int idx_peer = 2;
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	peer_description_unset(peer);

	return CMD_SUCCESS;
}

ALIAS(no_neighbor_description, no_neighbor_description_comment_cmd,
      "no neighbor <A.B.C.D|X:X::X:X|WORD> description LINE...",
      NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
      "Neighbor specific description\n"
      "Up to 80 characters describing this neighbor\n")

/* Neighbor update-source. */
static int peer_update_source_vty(struct vty *vty, const char *peer_str,
				  const char *source_str)
{
	struct peer *peer;
	struct prefix p;
	union sockunion su;

	peer = peer_and_group_lookup_vty(vty, peer_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	if (peer->conf_if)
		return CMD_WARNING;

	if (source_str) {
		if (str2sockunion(source_str, &su) == 0)
			peer_update_source_addr_set(peer, &su);
		else {
			if (str2prefix(source_str, &p)) {
				vty_out(vty,
					"%% Invalid update-source, remove prefix length \n");
				return CMD_WARNING_CONFIG_FAILED;
			} else
				peer_update_source_if_set(peer, source_str);
		}
	} else
		peer_update_source_unset(peer);

	return CMD_SUCCESS;
}

#define BGP_UPDATE_SOURCE_HELP_STR                                             \
	"IPv4 address\n"                                                       \
	"IPv6 address\n"                                                       \
	"Interface name (requires zebra to be running)\n"

DEFUN (neighbor_update_source,
       neighbor_update_source_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> update-source <A.B.C.D|X:X::X:X|WORD>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Source of routing updates\n"
       BGP_UPDATE_SOURCE_HELP_STR)
{
	int idx_peer = 1;
	int idx_peer_2 = 3;
	return peer_update_source_vty(vty, argv[idx_peer]->arg,
				      argv[idx_peer_2]->arg);
}

DEFUN (no_neighbor_update_source,
       no_neighbor_update_source_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> update-source [<A.B.C.D|X:X::X:X|WORD>]",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Source of routing updates\n"
       BGP_UPDATE_SOURCE_HELP_STR)
{
	int idx_peer = 2;
	return peer_update_source_vty(vty, argv[idx_peer]->arg, NULL);
}

static int peer_default_originate_set_vty(struct vty *vty, const char *peer_str,
					  afi_t afi, safi_t safi,
					  const char *rmap, int set)
{
	int ret;
	struct peer *peer;
	struct route_map *route_map = NULL;

	peer = peer_and_group_lookup_vty(vty, peer_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	if (set) {
		if (rmap)
			route_map = route_map_lookup_warn_noexist(vty, rmap);
		ret = peer_default_originate_set(peer, afi, safi,
						 rmap, route_map);
	} else
		ret = peer_default_originate_unset(peer, afi, safi);

	return bgp_vty_return(vty, ret);
}

/* neighbor default-originate. */
DEFUN (neighbor_default_originate,
       neighbor_default_originate_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> default-originate",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Originate default route to this neighbor\n")
{
	int idx_peer = 1;
	return peer_default_originate_set_vty(vty, argv[idx_peer]->arg,
					      bgp_node_afi(vty),
					      bgp_node_safi(vty), NULL, 1);
}

ALIAS_HIDDEN(neighbor_default_originate, neighbor_default_originate_hidden_cmd,
	     "neighbor <A.B.C.D|X:X::X:X|WORD> default-originate",
	     NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Originate default route to this neighbor\n")

DEFUN (neighbor_default_originate_rmap,
       neighbor_default_originate_rmap_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> default-originate route-map RMAP_NAME",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Originate default route to this neighbor\n"
       "Route-map to specify criteria to originate default\n"
       "route-map name\n")
{
	int idx_peer = 1;
	int idx_word = 4;
	return peer_default_originate_set_vty(
		vty, argv[idx_peer]->arg, bgp_node_afi(vty), bgp_node_safi(vty),
		argv[idx_word]->arg, 1);
}

ALIAS_HIDDEN(
	neighbor_default_originate_rmap,
	neighbor_default_originate_rmap_hidden_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD> default-originate route-map RMAP_NAME",
	NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	"Originate default route to this neighbor\n"
	"Route-map to specify criteria to originate default\n"
	"route-map name\n")

DEFUN (no_neighbor_default_originate,
       no_neighbor_default_originate_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> default-originate [route-map RMAP_NAME]",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Originate default route to this neighbor\n"
       "Route-map to specify criteria to originate default\n"
       "route-map name\n")
{
	int idx_peer = 2;
	return peer_default_originate_set_vty(vty, argv[idx_peer]->arg,
					      bgp_node_afi(vty),
					      bgp_node_safi(vty), NULL, 0);
}

ALIAS_HIDDEN(
	no_neighbor_default_originate, no_neighbor_default_originate_hidden_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD> default-originate [route-map RMAP_NAME]",
	NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	"Originate default route to this neighbor\n"
	"Route-map to specify criteria to originate default\n"
	"route-map name\n")


/* Set neighbor's BGP port.  */
static int peer_port_vty(struct vty *vty, const char *ip_str, int afi,
			 const char *port_str)
{
	struct peer *peer;
	uint16_t port;
	struct servent *sp;

	peer = peer_and_group_lookup_vty(vty, ip_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	if (!port_str) {
		sp = getservbyname("bgp", "tcp");
		port = (sp == NULL) ? BGP_PORT_DEFAULT : ntohs(sp->s_port);
	} else {
		port = strtoul(port_str, NULL, 10);
	}

	peer_port_set(peer, port);

	return CMD_SUCCESS;
}

/* Set specified peer's BGP port.  */
DEFUN (neighbor_port,
       neighbor_port_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> port (0-65535)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Neighbor's BGP port\n"
       "TCP port number\n")
{
	int idx_ip = 1;
	int idx_number = 3;
	return peer_port_vty(vty, argv[idx_ip]->arg, AFI_IP,
			     argv[idx_number]->arg);
}

DEFUN (no_neighbor_port,
       no_neighbor_port_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> port [(0-65535)]",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Neighbor's BGP port\n"
       "TCP port number\n")
{
	int idx_ip = 2;
	return peer_port_vty(vty, argv[idx_ip]->arg, AFI_IP, NULL);
}


/* neighbor weight. */
static int peer_weight_set_vty(struct vty *vty, const char *ip_str, afi_t afi,
			       safi_t safi, const char *weight_str)
{
	int ret;
	struct peer *peer;
	unsigned long weight;

	peer = peer_and_group_lookup_vty(vty, ip_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	weight = strtoul(weight_str, NULL, 10);

	ret = peer_weight_set(peer, afi, safi, weight);
	return bgp_vty_return(vty, ret);
}

static int peer_weight_unset_vty(struct vty *vty, const char *ip_str, afi_t afi,
				 safi_t safi)
{
	int ret;
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, ip_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	ret = peer_weight_unset(peer, afi, safi);
	return bgp_vty_return(vty, ret);
}

DEFUN (neighbor_weight,
       neighbor_weight_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> weight (0-65535)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Set default weight for routes from this neighbor\n"
       "default weight\n")
{
	int idx_peer = 1;
	int idx_number = 3;
	return peer_weight_set_vty(vty, argv[idx_peer]->arg, bgp_node_afi(vty),
				   bgp_node_safi(vty), argv[idx_number]->arg);
}

ALIAS_HIDDEN(neighbor_weight, neighbor_weight_hidden_cmd,
	     "neighbor <A.B.C.D|X:X::X:X|WORD> weight (0-65535)",
	     NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Set default weight for routes from this neighbor\n"
	     "default weight\n")

DEFUN (no_neighbor_weight,
       no_neighbor_weight_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> weight [(0-65535)]",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Set default weight for routes from this neighbor\n"
       "default weight\n")
{
	int idx_peer = 2;
	return peer_weight_unset_vty(vty, argv[idx_peer]->arg,
				     bgp_node_afi(vty), bgp_node_safi(vty));
}

ALIAS_HIDDEN(no_neighbor_weight, no_neighbor_weight_hidden_cmd,
	     "no neighbor <A.B.C.D|X:X::X:X|WORD> weight [(0-65535)]",
	     NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Set default weight for routes from this neighbor\n"
	     "default weight\n")


/* Override capability negotiation. */
DEFUN (neighbor_override_capability,
       neighbor_override_capability_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> override-capability",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Override capability negotiation result\n")
{
	int idx_peer = 1;
	return peer_flag_set_vty(vty, argv[idx_peer]->arg,
				 PEER_FLAG_OVERRIDE_CAPABILITY);
}

DEFUN (no_neighbor_override_capability,
       no_neighbor_override_capability_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> override-capability",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Override capability negotiation result\n")
{
	int idx_peer = 2;
	return peer_flag_unset_vty(vty, argv[idx_peer]->arg,
				   PEER_FLAG_OVERRIDE_CAPABILITY);
}

DEFUN (neighbor_strict_capability,
       neighbor_strict_capability_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> strict-capability-match",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Strict capability negotiation match\n")
{
	int idx_peer = 1;

	return peer_flag_set_vty(vty, argv[idx_peer]->arg,
				 PEER_FLAG_STRICT_CAP_MATCH);
}

DEFUN (no_neighbor_strict_capability,
       no_neighbor_strict_capability_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> strict-capability-match",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Strict capability negotiation match\n")
{
	int idx_peer = 2;

	return peer_flag_unset_vty(vty, argv[idx_peer]->arg,
				   PEER_FLAG_STRICT_CAP_MATCH);
}

static int peer_timers_set_vty(struct vty *vty, const char *ip_str,
			       const char *keep_str, const char *hold_str)
{
	int ret;
	struct peer *peer;
	uint32_t keepalive;
	uint32_t holdtime;

	peer = peer_and_group_lookup_vty(vty, ip_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	keepalive = strtoul(keep_str, NULL, 10);
	holdtime = strtoul(hold_str, NULL, 10);

	ret = peer_timers_set(peer, keepalive, holdtime);

	return bgp_vty_return(vty, ret);
}

static int peer_timers_unset_vty(struct vty *vty, const char *ip_str)
{
	int ret;
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, ip_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	ret = peer_timers_unset(peer);

	return bgp_vty_return(vty, ret);
}

DEFUN (neighbor_timers,
       neighbor_timers_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> timers (0-65535) (0-65535)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP per neighbor timers\n"
       "Keepalive interval\n"
       "Holdtime\n")
{
	int idx_peer = 1;
	int idx_number = 3;
	int idx_number_2 = 4;
	return peer_timers_set_vty(vty, argv[idx_peer]->arg,
				   argv[idx_number]->arg,
				   argv[idx_number_2]->arg);
}

DEFUN (no_neighbor_timers,
       no_neighbor_timers_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> timers [(0-65535) (0-65535)]",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP per neighbor timers\n"
       "Keepalive interval\n"
       "Holdtime\n")
{
	int idx_peer = 2;
	return peer_timers_unset_vty(vty, argv[idx_peer]->arg);
}


static int peer_timers_connect_set_vty(struct vty *vty, const char *ip_str,
				       const char *time_str)
{
	int ret;
	struct peer *peer;
	uint32_t connect;

	peer = peer_and_group_lookup_vty(vty, ip_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	connect = strtoul(time_str, NULL, 10);

	ret = peer_timers_connect_set(peer, connect);

	return bgp_vty_return(vty, ret);
}

static int peer_timers_connect_unset_vty(struct vty *vty, const char *ip_str)
{
	int ret;
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, ip_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	ret = peer_timers_connect_unset(peer);

	return bgp_vty_return(vty, ret);
}

DEFUN (neighbor_timers_connect,
       neighbor_timers_connect_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> timers connect (1-65535)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP per neighbor timers\n"
       "BGP connect timer\n"
       "Connect timer\n")
{
	int idx_peer = 1;
	int idx_number = 4;
	return peer_timers_connect_set_vty(vty, argv[idx_peer]->arg,
					   argv[idx_number]->arg);
}

DEFUN (no_neighbor_timers_connect,
       no_neighbor_timers_connect_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> timers connect [(1-65535)]",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP per neighbor timers\n"
       "BGP connect timer\n"
       "Connect timer\n")
{
	int idx_peer = 2;
	return peer_timers_connect_unset_vty(vty, argv[idx_peer]->arg);
}

DEFPY (neighbor_timers_delayopen,
       neighbor_timers_delayopen_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor timers delayopen (1-240)$interval",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP per neighbor timers\n"
       "RFC 4271 DelayOpenTimer\n"
       "DelayOpenTime timer interval\n")
{
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, neighbor);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	if (!interval) {
		if (peer_timers_delayopen_unset(peer))
			return CMD_WARNING_CONFIG_FAILED;
	} else {
		if (peer_timers_delayopen_set(peer, interval))
			return CMD_WARNING_CONFIG_FAILED;
	}

	return CMD_SUCCESS;
}

DEFPY (no_neighbor_timers_delayopen,
       no_neighbor_timers_delayopen_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor timers delayopen [(0-65535)]",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP per neighbor timers\n"
       "RFC 4271 DelayOpenTimer\n"
       "DelayOpenTime timer interval\n")
{
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, neighbor);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	if (peer_timers_delayopen_unset(peer))
		return CMD_WARNING_CONFIG_FAILED;

	return CMD_SUCCESS;
}

static int peer_advertise_interval_vty(struct vty *vty, const char *ip_str,
				       const char *time_str, int set)
{
	int ret;
	struct peer *peer;
	uint32_t routeadv = 0;

	peer = peer_and_group_lookup_vty(vty, ip_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	if (time_str)
		routeadv = strtoul(time_str, NULL, 10);

	if (set)
		ret = peer_advertise_interval_set(peer, routeadv);
	else
		ret = peer_advertise_interval_unset(peer);

	return bgp_vty_return(vty, ret);
}

DEFUN (neighbor_advertise_interval,
       neighbor_advertise_interval_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> advertisement-interval (0-600)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Minimum interval between sending BGP routing updates\n"
       "time in seconds\n")
{
	int idx_peer = 1;
	int idx_number = 3;
	return peer_advertise_interval_vty(vty, argv[idx_peer]->arg,
					   argv[idx_number]->arg, 1);
}

DEFUN (no_neighbor_advertise_interval,
       no_neighbor_advertise_interval_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> advertisement-interval [(0-600)]",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Minimum interval between sending BGP routing updates\n"
       "time in seconds\n")
{
	int idx_peer = 2;
	return peer_advertise_interval_vty(vty, argv[idx_peer]->arg, NULL, 0);
}


/* Time to wait before processing route-map updates */
DEFUN (bgp_set_route_map_delay_timer,
       bgp_set_route_map_delay_timer_cmd,
       "bgp route-map delay-timer (0-600)",
       SET_STR
       "BGP route-map delay timer\n"
       "Time in secs to wait before processing route-map changes\n"
       "0 disables the timer, no route updates happen when route-maps change\n")
{
	int idx_number = 3;
	uint32_t rmap_delay_timer;

	if (argv[idx_number]->arg) {
		rmap_delay_timer = strtoul(argv[idx_number]->arg, NULL, 10);
		bm->rmap_update_timer = rmap_delay_timer;

		/* if the dynamic update handling is being disabled, and a timer
		 * is
		 * running, stop the timer and act as if the timer has already
		 * fired.
		 */
		if (!rmap_delay_timer && bm->t_rmap_update) {
			EVENT_OFF(bm->t_rmap_update);
			event_execute(bm->master, bgp_route_map_update_timer,
				      NULL, 0, NULL);
		}
		return CMD_SUCCESS;
	} else {
		vty_out(vty, "%% BGP invalid route-map delay-timer\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
}

DEFUN (no_bgp_set_route_map_delay_timer,
       no_bgp_set_route_map_delay_timer_cmd,
       "no bgp route-map delay-timer [(0-600)]",
       NO_STR
       BGP_STR
       "Default BGP route-map delay timer\n"
       "Reset to default time to wait for processing route-map changes\n"
       "0 disables the timer, no route updates happen when route-maps change\n")
{

	bm->rmap_update_timer = RMAP_DEFAULT_UPDATE_TIMER;

	return CMD_SUCCESS;
}

/* neighbor interface */
static int peer_interface_vty(struct vty *vty, const char *ip_str,
			      const char *str)
{
	struct peer *peer;

	peer = peer_lookup_vty(vty, ip_str);
	if (!peer || peer->conf_if) {
		vty_out(vty, "%% BGP invalid peer %s\n", ip_str);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (str)
		peer_interface_set(peer, str);
	else
		peer_interface_unset(peer);

	return CMD_SUCCESS;
}

DEFUN (neighbor_interface,
       neighbor_interface_cmd,
       "neighbor <A.B.C.D|X:X::X:X> interface WORD",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Interface\n"
       "Interface name\n")
{
	int idx_ip = 1;
	int idx_word = 3;

	return peer_interface_vty(vty, argv[idx_ip]->arg, argv[idx_word]->arg);
}

DEFUN (no_neighbor_interface,
       no_neighbor_interface_cmd,
       "no neighbor <A.B.C.D|X:X::X:X> interface WORD",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Interface\n"
       "Interface name\n")
{
	int idx_peer = 2;

	return peer_interface_vty(vty, argv[idx_peer]->arg, NULL);
}

DEFUN (neighbor_distribute_list,
       neighbor_distribute_list_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> distribute-list ACCESSLIST_NAME <in|out>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Filter updates to/from this neighbor\n"
       "IP Access-list name\n"
       "Filter incoming updates\n"
       "Filter outgoing updates\n")
{
	int idx_peer = 1;
	int idx_acl = 3;
	int direct, ret;
	struct peer *peer;

	const char *pstr = argv[idx_peer]->arg;
	const char *acl = argv[idx_acl]->arg;
	const char *inout = argv[argc - 1]->text;

	peer = peer_and_group_lookup_vty(vty, pstr);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	/* Check filter direction. */
	direct = strmatch(inout, "in") ? FILTER_IN : FILTER_OUT;
	ret = peer_distribute_set(peer, bgp_node_afi(vty), bgp_node_safi(vty),
				  direct, acl);

	return bgp_vty_return(vty, ret);
}

ALIAS_HIDDEN(
	neighbor_distribute_list, neighbor_distribute_list_hidden_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD> distribute-list ACCESSLIST_NAME <in|out>",
	NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	"Filter updates to/from this neighbor\n"
	"IP Access-list name\n"
	"Filter incoming updates\n"
	"Filter outgoing updates\n")

DEFUN (no_neighbor_distribute_list,
       no_neighbor_distribute_list_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> distribute-list ACCESSLIST_NAME <in|out>",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Filter updates to/from this neighbor\n"
       "IP Access-list name\n"
       "Filter incoming updates\n"
       "Filter outgoing updates\n")
{
	int idx_peer = 2;
	int direct, ret;
	struct peer *peer;

	const char *pstr = argv[idx_peer]->arg;
	const char *inout = argv[argc - 1]->text;

	peer = peer_and_group_lookup_vty(vty, pstr);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	/* Check filter direction. */
	direct = strmatch(inout, "in") ? FILTER_IN : FILTER_OUT;
	ret = peer_distribute_unset(peer, bgp_node_afi(vty), bgp_node_safi(vty),
				    direct);

	return bgp_vty_return(vty, ret);
}

ALIAS_HIDDEN(
	no_neighbor_distribute_list, no_neighbor_distribute_list_hidden_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD> distribute-list ACCESSLIST_NAME <in|out>",
	NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	"Filter updates to/from this neighbor\n"
	"IP Access-list name\n"
	"Filter incoming updates\n"
	"Filter outgoing updates\n")

/* Set prefix list to the peer. */
static int peer_prefix_list_set_vty(struct vty *vty, const char *ip_str,
				    afi_t afi, safi_t safi,
				    const char *name_str,
				    const char *direct_str)
{
	int ret;
	int direct = FILTER_IN;
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, ip_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	/* Check filter direction. */
	if (strncmp(direct_str, "i", 1) == 0)
		direct = FILTER_IN;
	else if (strncmp(direct_str, "o", 1) == 0)
		direct = FILTER_OUT;

	ret = peer_prefix_list_set(peer, afi, safi, direct, name_str);

	return bgp_vty_return(vty, ret);
}

static int peer_prefix_list_unset_vty(struct vty *vty, const char *ip_str,
				      afi_t afi, safi_t safi,
				      const char *direct_str)
{
	int ret;
	struct peer *peer;
	int direct = FILTER_IN;

	peer = peer_and_group_lookup_vty(vty, ip_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	/* Check filter direction. */
	if (strncmp(direct_str, "i", 1) == 0)
		direct = FILTER_IN;
	else if (strncmp(direct_str, "o", 1) == 0)
		direct = FILTER_OUT;

	ret = peer_prefix_list_unset(peer, afi, safi, direct);

	return bgp_vty_return(vty, ret);
}

DEFUN (neighbor_prefix_list,
       neighbor_prefix_list_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> prefix-list WORD <in|out>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Filter updates to/from this neighbor\n"
       "Name of a prefix list\n"
       "Filter incoming updates\n"
       "Filter outgoing updates\n")
{
	int idx_peer = 1;
	int idx_word = 3;
	int idx_in_out = 4;
	return peer_prefix_list_set_vty(
		vty, argv[idx_peer]->arg, bgp_node_afi(vty), bgp_node_safi(vty),
		argv[idx_word]->arg, argv[idx_in_out]->arg);
}

ALIAS_HIDDEN(neighbor_prefix_list, neighbor_prefix_list_hidden_cmd,
	     "neighbor <A.B.C.D|X:X::X:X|WORD> prefix-list WORD <in|out>",
	     NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Filter updates to/from this neighbor\n"
	     "Name of a prefix list\n"
	     "Filter incoming updates\n"
	     "Filter outgoing updates\n")

DEFUN (no_neighbor_prefix_list,
       no_neighbor_prefix_list_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> prefix-list WORD <in|out>",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Filter updates to/from this neighbor\n"
       "Name of a prefix list\n"
       "Filter incoming updates\n"
       "Filter outgoing updates\n")
{
	int idx_peer = 2;
	int idx_in_out = 5;
	return peer_prefix_list_unset_vty(vty, argv[idx_peer]->arg,
					  bgp_node_afi(vty), bgp_node_safi(vty),
					  argv[idx_in_out]->arg);
}

ALIAS_HIDDEN(no_neighbor_prefix_list, no_neighbor_prefix_list_hidden_cmd,
	     "no neighbor <A.B.C.D|X:X::X:X|WORD> prefix-list WORD <in|out>",
	     NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Filter updates to/from this neighbor\n"
	     "Name of a prefix list\n"
	     "Filter incoming updates\n"
	     "Filter outgoing updates\n")

static int peer_aslist_set_vty(struct vty *vty, const char *ip_str, afi_t afi,
			       safi_t safi, const char *name_str,
			       const char *direct_str)
{
	int ret;
	struct peer *peer;
	int direct = FILTER_IN;

	peer = peer_and_group_lookup_vty(vty, ip_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	/* Check filter direction. */
	if (strncmp(direct_str, "i", 1) == 0)
		direct = FILTER_IN;
	else if (strncmp(direct_str, "o", 1) == 0)
		direct = FILTER_OUT;

	ret = peer_aslist_set(peer, afi, safi, direct, name_str);

	return bgp_vty_return(vty, ret);
}

static int peer_aslist_unset_vty(struct vty *vty, const char *ip_str, afi_t afi,
				 safi_t safi, const char *direct_str)
{
	int ret;
	struct peer *peer;
	int direct = FILTER_IN;

	peer = peer_and_group_lookup_vty(vty, ip_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	/* Check filter direction. */
	if (strncmp(direct_str, "i", 1) == 0)
		direct = FILTER_IN;
	else if (strncmp(direct_str, "o", 1) == 0)
		direct = FILTER_OUT;

	ret = peer_aslist_unset(peer, afi, safi, direct);

	return bgp_vty_return(vty, ret);
}

DEFUN (neighbor_filter_list,
       neighbor_filter_list_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> filter-list AS_PATH_FILTER_NAME <in|out>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Establish BGP filters\n"
       "AS path access-list name\n"
       "Filter incoming routes\n"
       "Filter outgoing routes\n")
{
	int idx_peer = 1;
	int idx_word = 3;
	int idx_in_out = 4;
	return peer_aslist_set_vty(vty, argv[idx_peer]->arg, bgp_node_afi(vty),
				   bgp_node_safi(vty), argv[idx_word]->arg,
				   argv[idx_in_out]->arg);
}

ALIAS_HIDDEN(neighbor_filter_list, neighbor_filter_list_hidden_cmd,
	     "neighbor <A.B.C.D|X:X::X:X|WORD> filter-list AS_PATH_FILTER_NAME <in|out>",
	     NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Establish BGP filters\n"
	     "AS path access-list name\n"
	     "Filter incoming routes\n"
	     "Filter outgoing routes\n")

DEFUN (no_neighbor_filter_list,
       no_neighbor_filter_list_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> filter-list AS_PATH_FILTER_NAME <in|out>",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Establish BGP filters\n"
       "AS path access-list name\n"
       "Filter incoming routes\n"
       "Filter outgoing routes\n")
{
	int idx_peer = 2;
	int idx_in_out = 5;
	return peer_aslist_unset_vty(vty, argv[idx_peer]->arg,
				     bgp_node_afi(vty), bgp_node_safi(vty),
				     argv[idx_in_out]->arg);
}

ALIAS_HIDDEN(no_neighbor_filter_list, no_neighbor_filter_list_hidden_cmd,
	     "no neighbor <A.B.C.D|X:X::X:X|WORD> filter-list AS_PATH_FILTER_NAME <in|out>",
	     NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Establish BGP filters\n"
	     "AS path access-list name\n"
	     "Filter incoming routes\n"
	     "Filter outgoing routes\n")

/* Set advertise-map to the peer. */
static int peer_advertise_map_set_vty(struct vty *vty, const char *ip_str,
				      afi_t afi, safi_t safi,
				      const char *advertise_str,
				      const char *condition_str, bool condition,
				      bool set)
{
	int ret = CMD_WARNING_CONFIG_FAILED;
	struct peer *peer;
	struct route_map *advertise_map;
	struct route_map *condition_map;

	peer = peer_and_group_lookup_vty(vty, ip_str);
	if (!peer)
		return ret;

	condition_map = route_map_lookup_warn_noexist(vty, condition_str);
	advertise_map = route_map_lookup_warn_noexist(vty, advertise_str);

	if (set)
		ret = peer_advertise_map_set(peer, afi, safi, advertise_str,
					     advertise_map, condition_str,
					     condition_map, condition);
	else
		ret = peer_advertise_map_unset(peer, afi, safi, advertise_str,
					       advertise_map, condition_str,
					       condition_map, condition);

	return bgp_vty_return(vty, ret);
}

DEFPY (bgp_condadv_period,
       bgp_condadv_period_cmd,
       "[no$no] bgp conditional-advertisement timer (5-240)$period",
       NO_STR
       BGP_STR
       "Conditional advertisement settings\n"
       "Set period to rescan BGP table to check if condition is met\n"
       "Period between BGP table scans, in seconds; default 60\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	bgp->condition_check_period =
		no ? DEFAULT_CONDITIONAL_ROUTES_POLL_TIME : period;

	return CMD_SUCCESS;
}

DEFPY (bgp_def_originate_eval,
       bgp_def_originate_eval_cmd,
       "[no$no] bgp default-originate timer (0-65535)$timer",
       NO_STR
       BGP_STR
       "Control default-originate\n"
       "Set period to rescan BGP table to check if default-originate condition is met\n"
       "Period between BGP table scans, in seconds; default 5\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	bgp->rmap_def_originate_eval_timer = no ? 0 : timer;

	if (bgp->t_rmap_def_originate_eval)
		EVENT_OFF(bgp->t_rmap_def_originate_eval);

	return CMD_SUCCESS;
}

DEFPY (neighbor_advertise_map,
       neighbor_advertise_map_cmd,
       "[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor advertise-map RMAP_NAME$advertise_str <exist-map|non-exist-map>$exist RMAP_NAME$condition_str",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Route-map to conditionally advertise routes\n"
       "Name of advertise map\n"
       "Advertise routes only if prefixes in exist-map are installed in BGP table\n"
       "Advertise routes only if prefixes in non-exist-map are not installed in BGP table\n"
       "Name of the exist or non exist map\n")
{
	bool condition = CONDITION_EXIST;

	if (!strcmp(exist, "non-exist-map"))
		condition = CONDITION_NON_EXIST;

	return peer_advertise_map_set_vty(vty, neighbor, bgp_node_afi(vty),
					  bgp_node_safi(vty), advertise_str,
					  condition_str, condition, !no);
}

ALIAS_HIDDEN(neighbor_advertise_map, neighbor_advertise_map_hidden_cmd,
	     "[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor advertise-map RMAP_NAME$advertise_str <exist-map|non-exist-map>$exist RMAP_NAME$condition_str",
	     NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Route-map to conditionally advertise routes\n"
	     "Name of advertise map\n"
	     "Advertise routes only if prefixes in exist-map are installed in BGP table\n"
	     "Advertise routes only if prefixes in non-exist-map are not installed in BGP table\n"
	     "Name of the exist or non exist map\n")

/* Set route-map to the peer. */
static int peer_route_map_set_vty(struct vty *vty, const char *ip_str,
				  afi_t afi, safi_t safi, const char *name_str,
				  const char *direct_str)
{
	int ret;
	struct peer *peer;
	int direct = RMAP_IN;
	struct route_map *route_map;

	peer = peer_and_group_lookup_vty(vty, ip_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	/* Check filter direction. */
	if (strncmp(direct_str, "in", 2) == 0)
		direct = RMAP_IN;
	else if (strncmp(direct_str, "o", 1) == 0)
		direct = RMAP_OUT;

	route_map = route_map_lookup_warn_noexist(vty, name_str);
	ret = peer_route_map_set(peer, afi, safi, direct, name_str, route_map);

	return bgp_vty_return(vty, ret);
}

static int peer_route_map_unset_vty(struct vty *vty, const char *ip_str,
				    afi_t afi, safi_t safi,
				    const char *direct_str)
{
	int ret;
	struct peer *peer;
	int direct = RMAP_IN;

	peer = peer_and_group_lookup_vty(vty, ip_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	/* Check filter direction. */
	if (strncmp(direct_str, "in", 2) == 0)
		direct = RMAP_IN;
	else if (strncmp(direct_str, "o", 1) == 0)
		direct = RMAP_OUT;

	ret = peer_route_map_unset(peer, afi, safi, direct);

	return bgp_vty_return(vty, ret);
}

DEFUN (neighbor_route_map,
       neighbor_route_map_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> route-map RMAP_NAME <in|out>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Apply route map to neighbor\n"
       "Name of route map\n"
       "Apply map to incoming routes\n"
       "Apply map to outbound routes\n")
{
	int idx_peer = 1;
	int idx_word = 3;
	int idx_in_out = 4;
	return peer_route_map_set_vty(
		vty, argv[idx_peer]->arg, bgp_node_afi(vty), bgp_node_safi(vty),
		argv[idx_word]->arg, argv[idx_in_out]->arg);
}

ALIAS_HIDDEN(neighbor_route_map, neighbor_route_map_hidden_cmd,
	     "neighbor <A.B.C.D|X:X::X:X|WORD> route-map RMAP_NAME <in|out>",
	     NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Apply route map to neighbor\n"
	     "Name of route map\n"
	     "Apply map to incoming routes\n"
	     "Apply map to outbound routes\n")

DEFUN (no_neighbor_route_map,
       no_neighbor_route_map_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> route-map RMAP_NAME <in|out>",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Apply route map to neighbor\n"
       "Name of route map\n"
       "Apply map to incoming routes\n"
       "Apply map to outbound routes\n")
{
	int idx_peer = 2;
	int idx_in_out = 5;
	return peer_route_map_unset_vty(vty, argv[idx_peer]->arg,
					bgp_node_afi(vty), bgp_node_safi(vty),
					argv[idx_in_out]->arg);
}

ALIAS_HIDDEN(no_neighbor_route_map, no_neighbor_route_map_hidden_cmd,
	     "no neighbor <A.B.C.D|X:X::X:X|WORD> route-map RMAP_NAME <in|out>",
	     NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Apply route map to neighbor\n"
	     "Name of route map\n"
	     "Apply map to incoming routes\n"
	     "Apply map to outbound routes\n")

/* Set unsuppress-map to the peer. */
static int peer_unsuppress_map_set_vty(struct vty *vty, const char *ip_str,
				       afi_t afi, safi_t safi,
				       const char *name_str)
{
	int ret;
	struct peer *peer;
	struct route_map *route_map;

	peer = peer_and_group_lookup_vty(vty, ip_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	route_map = route_map_lookup_warn_noexist(vty, name_str);
	ret = peer_unsuppress_map_set(peer, afi, safi, name_str, route_map);

	return bgp_vty_return(vty, ret);
}

/* Unset route-map from the peer. */
static int peer_unsuppress_map_unset_vty(struct vty *vty, const char *ip_str,
					 afi_t afi, safi_t safi)
{
	int ret;
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, ip_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	ret = peer_unsuppress_map_unset(peer, afi, safi);

	return bgp_vty_return(vty, ret);
}

DEFUN (neighbor_unsuppress_map,
       neighbor_unsuppress_map_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> unsuppress-map WORD",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Route-map to selectively unsuppress suppressed routes\n"
       "Name of route map\n")
{
	int idx_peer = 1;
	int idx_word = 3;
	return peer_unsuppress_map_set_vty(
		vty, argv[idx_peer]->arg, bgp_node_afi(vty), bgp_node_safi(vty),
		argv[idx_word]->arg);
}

ALIAS_HIDDEN(neighbor_unsuppress_map, neighbor_unsuppress_map_hidden_cmd,
	     "neighbor <A.B.C.D|X:X::X:X|WORD> unsuppress-map WORD",
	     NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Route-map to selectively unsuppress suppressed routes\n"
	     "Name of route map\n")

DEFUN (no_neighbor_unsuppress_map,
       no_neighbor_unsuppress_map_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> unsuppress-map WORD",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Route-map to selectively unsuppress suppressed routes\n"
       "Name of route map\n")
{
	int idx_peer = 2;
	return peer_unsuppress_map_unset_vty(vty, argv[idx_peer]->arg,
					     bgp_node_afi(vty),
					     bgp_node_safi(vty));
}

ALIAS_HIDDEN(no_neighbor_unsuppress_map, no_neighbor_unsuppress_map_hidden_cmd,
	     "no neighbor <A.B.C.D|X:X::X:X|WORD> unsuppress-map WORD",
	     NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Route-map to selectively unsuppress suppressed routes\n"
	     "Name of route map\n")

static int peer_maximum_prefix_set_vty(struct vty *vty, const char *ip_str,
				       afi_t afi, safi_t safi,
				       const char *num_str,
				       const char *threshold_str, int warning,
				       const char *restart_str,
				       const char *force_str)
{
	int ret;
	struct peer *peer;
	uint32_t max;
	uint8_t threshold;
	uint16_t restart;

	peer = peer_and_group_lookup_vty(vty, ip_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	max = strtoul(num_str, NULL, 10);
	if (threshold_str)
		threshold = atoi(threshold_str);
	else
		threshold = MAXIMUM_PREFIX_THRESHOLD_DEFAULT;

	if (restart_str)
		restart = atoi(restart_str);
	else
		restart = 0;

	ret = peer_maximum_prefix_set(peer, afi, safi, max, threshold, warning,
				      restart, force_str ? true : false);

	return bgp_vty_return(vty, ret);
}

static int peer_maximum_prefix_unset_vty(struct vty *vty, const char *ip_str,
					 afi_t afi, safi_t safi)
{
	int ret;
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, ip_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	ret = peer_maximum_prefix_unset(peer, afi, safi);

	return bgp_vty_return(vty, ret);
}

/* Maximum number of prefix to be sent to the neighbor. */
DEFUN(neighbor_maximum_prefix_out,
      neighbor_maximum_prefix_out_cmd,
      "neighbor <A.B.C.D|X:X::X:X|WORD> maximum-prefix-out (1-4294967295)",
      NEIGHBOR_STR
      NEIGHBOR_ADDR_STR2
      "Maximum number of prefixes to be sent to this peer\n"
      "Maximum no. of prefix limit\n")
{
	int ret;
	int idx_peer = 1;
	int idx_number = 3;
	struct peer *peer;
	uint32_t max;
	afi_t afi = bgp_node_afi(vty);
	safi_t safi = bgp_node_safi(vty);

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	max = strtoul(argv[idx_number]->arg, NULL, 10);

	ret = peer_maximum_prefix_out_set(peer, afi, safi, max);

	return bgp_vty_return(vty, ret);
}

DEFUN(no_neighbor_maximum_prefix_out,
      no_neighbor_maximum_prefix_out_cmd,
      "no neighbor <A.B.C.D|X:X::X:X|WORD> maximum-prefix-out [(1-4294967295)]",
      NO_STR
      NEIGHBOR_STR
      NEIGHBOR_ADDR_STR2
      "Maximum number of prefixes to be sent to this peer\n"
      "Maximum no. of prefix limit\n")
{
	int ret;
	int idx_peer = 2;
	struct peer *peer;
	afi_t afi = bgp_node_afi(vty);
	safi_t safi = bgp_node_safi(vty);

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	ret = peer_maximum_prefix_out_unset(peer, afi, safi);

	return bgp_vty_return(vty, ret);
}

/* Maximum number of prefix configuration. Prefix count is different
   for each peer configuration. So this configuration can be set for
   each peer configuration. */
DEFUN (neighbor_maximum_prefix,
       neighbor_maximum_prefix_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> maximum-prefix (1-4294967295) [force]",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Maximum number of prefix accept from this peer\n"
       "maximum no. of prefix limit\n"
       "Force checking all received routes not only accepted\n")
{
	int idx_peer = 1;
	int idx_number = 3;
	int idx_force = 0;
	char *force = NULL;

	if (argv_find(argv, argc, "force", &idx_force))
		force = argv[idx_force]->arg;

	return peer_maximum_prefix_set_vty(
		vty, argv[idx_peer]->arg, bgp_node_afi(vty), bgp_node_safi(vty),
		argv[idx_number]->arg, NULL, 0, NULL, force);
}

ALIAS_HIDDEN(neighbor_maximum_prefix, neighbor_maximum_prefix_hidden_cmd,
	     "neighbor <A.B.C.D|X:X::X:X|WORD> maximum-prefix (1-4294967295) [force]",
	     NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Maximum number of prefix accept from this peer\n"
	     "maximum no. of prefix limit\n"
	     "Force checking all received routes not only accepted\n")

DEFUN (neighbor_maximum_prefix_threshold,
       neighbor_maximum_prefix_threshold_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> maximum-prefix (1-4294967295) (1-100) [force]",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Maximum number of prefix accept from this peer\n"
       "maximum no. of prefix limit\n"
       "Threshold value (%) at which to generate a warning msg\n"
       "Force checking all received routes not only accepted\n")
{
	int idx_peer = 1;
	int idx_number = 3;
	int idx_number_2 = 4;
	int idx_force = 0;
	char *force = NULL;

	if (argv_find(argv, argc, "force", &idx_force))
		force = argv[idx_force]->arg;

	return peer_maximum_prefix_set_vty(
		vty, argv[idx_peer]->arg, bgp_node_afi(vty), bgp_node_safi(vty),
		argv[idx_number]->arg, argv[idx_number_2]->arg, 0, NULL, force);
}

ALIAS_HIDDEN(
	neighbor_maximum_prefix_threshold,
	neighbor_maximum_prefix_threshold_hidden_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD> maximum-prefix (1-4294967295) (1-100) [force]",
	NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	"Maximum number of prefix accept from this peer\n"
	"maximum no. of prefix limit\n"
	"Threshold value (%) at which to generate a warning msg\n"
	"Force checking all received routes not only accepted\n")

DEFUN (neighbor_maximum_prefix_warning,
       neighbor_maximum_prefix_warning_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> maximum-prefix (1-4294967295) warning-only [force]",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Maximum number of prefix accept from this peer\n"
       "maximum no. of prefix limit\n"
       "Only give warning message when limit is exceeded\n"
       "Force checking all received routes not only accepted\n")
{
	int idx_peer = 1;
	int idx_number = 3;
	int idx_force = 0;
	char *force = NULL;

	if (argv_find(argv, argc, "force", &idx_force))
		force = argv[idx_force]->arg;

	return peer_maximum_prefix_set_vty(
		vty, argv[idx_peer]->arg, bgp_node_afi(vty), bgp_node_safi(vty),
		argv[idx_number]->arg, NULL, 1, NULL, force);
}

ALIAS_HIDDEN(
	neighbor_maximum_prefix_warning,
	neighbor_maximum_prefix_warning_hidden_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD> maximum-prefix (1-4294967295) warning-only [force]",
	NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	"Maximum number of prefix accept from this peer\n"
	"maximum no. of prefix limit\n"
	"Only give warning message when limit is exceeded\n"
	"Force checking all received routes not only accepted\n")

DEFUN (neighbor_maximum_prefix_threshold_warning,
       neighbor_maximum_prefix_threshold_warning_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> maximum-prefix (1-4294967295) (1-100) warning-only [force]",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Maximum number of prefix accept from this peer\n"
       "maximum no. of prefix limit\n"
       "Threshold value (%) at which to generate a warning msg\n"
       "Only give warning message when limit is exceeded\n"
       "Force checking all received routes not only accepted\n")
{
	int idx_peer = 1;
	int idx_number = 3;
	int idx_number_2 = 4;
	int idx_force = 0;
	char *force = NULL;

	if (argv_find(argv, argc, "force", &idx_force))
		force = argv[idx_force]->arg;

	return peer_maximum_prefix_set_vty(
		vty, argv[idx_peer]->arg, bgp_node_afi(vty), bgp_node_safi(vty),
		argv[idx_number]->arg, argv[idx_number_2]->arg, 1, NULL, force);
}

ALIAS_HIDDEN(
	neighbor_maximum_prefix_threshold_warning,
	neighbor_maximum_prefix_threshold_warning_hidden_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD> maximum-prefix (1-4294967295) (1-100) warning-only [force]",
	NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	"Maximum number of prefix accept from this peer\n"
	"maximum no. of prefix limit\n"
	"Threshold value (%) at which to generate a warning msg\n"
	"Only give warning message when limit is exceeded\n"
	"Force checking all received routes not only accepted\n")

DEFUN (neighbor_maximum_prefix_restart,
       neighbor_maximum_prefix_restart_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> maximum-prefix (1-4294967295) restart (1-65535) [force]",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Maximum number of prefix accept from this peer\n"
       "maximum no. of prefix limit\n"
       "Restart bgp connection after limit is exceeded\n"
       "Restart interval in minutes\n"
       "Force checking all received routes not only accepted\n")
{
	int idx_peer = 1;
	int idx_number = 3;
	int idx_number_2 = 5;
	int idx_force = 0;
	char *force = NULL;

	if (argv_find(argv, argc, "force", &idx_force))
		force = argv[idx_force]->arg;

	return peer_maximum_prefix_set_vty(
		vty, argv[idx_peer]->arg, bgp_node_afi(vty), bgp_node_safi(vty),
		argv[idx_number]->arg, NULL, 0, argv[idx_number_2]->arg, force);
}

ALIAS_HIDDEN(
	neighbor_maximum_prefix_restart,
	neighbor_maximum_prefix_restart_hidden_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD> maximum-prefix (1-4294967295) restart (1-65535) [force]",
	NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	"Maximum number of prefix accept from this peer\n"
	"maximum no. of prefix limit\n"
	"Restart bgp connection after limit is exceeded\n"
	"Restart interval in minutes\n"
	"Force checking all received routes not only accepted\n")

DEFUN (neighbor_maximum_prefix_threshold_restart,
       neighbor_maximum_prefix_threshold_restart_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> maximum-prefix (1-4294967295) (1-100) restart (1-65535) [force]",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Maximum number of prefixes to accept from this peer\n"
       "maximum no. of prefix limit\n"
       "Threshold value (%) at which to generate a warning msg\n"
       "Restart bgp connection after limit is exceeded\n"
       "Restart interval in minutes\n"
       "Force checking all received routes not only accepted\n")
{
	int idx_peer = 1;
	int idx_number = 3;
	int idx_number_2 = 4;
	int idx_number_3 = 6;
	int idx_force = 0;
	char *force = NULL;

	if (argv_find(argv, argc, "force", &idx_force))
		force = argv[idx_force]->arg;

	return peer_maximum_prefix_set_vty(
		vty, argv[idx_peer]->arg, bgp_node_afi(vty), bgp_node_safi(vty),
		argv[idx_number]->arg, argv[idx_number_2]->arg, 0,
		argv[idx_number_3]->arg, force);
}

ALIAS_HIDDEN(
	neighbor_maximum_prefix_threshold_restart,
	neighbor_maximum_prefix_threshold_restart_hidden_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD> maximum-prefix (1-4294967295) (1-100) restart (1-65535) [force]",
	NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	"Maximum number of prefixes to accept from this peer\n"
	"maximum no. of prefix limit\n"
	"Threshold value (%) at which to generate a warning msg\n"
	"Restart bgp connection after limit is exceeded\n"
	"Restart interval in minutes\n"
	"Force checking all received routes not only accepted\n")

DEFUN (no_neighbor_maximum_prefix,
       no_neighbor_maximum_prefix_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> maximum-prefix [(1-4294967295) [(1-100)] [restart (1-65535)] [warning-only] [force]]",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Maximum number of prefixes to accept from this peer\n"
       "maximum no. of prefix limit\n"
       "Threshold value (%) at which to generate a warning msg\n"
       "Restart bgp connection after limit is exceeded\n"
       "Restart interval in minutes\n"
       "Only give warning message when limit is exceeded\n"
       "Force checking all received routes not only accepted\n")
{
	int idx_peer = 2;
	return peer_maximum_prefix_unset_vty(vty, argv[idx_peer]->arg,
					     bgp_node_afi(vty),
					     bgp_node_safi(vty));
}

ALIAS_HIDDEN(
	no_neighbor_maximum_prefix, no_neighbor_maximum_prefix_hidden_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD> maximum-prefix [(1-4294967295) [(1-100)] [restart (1-65535)] [warning-only] [force]]",
	NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	"Maximum number of prefixes to accept from this peer\n"
	"maximum no. of prefix limit\n"
	"Threshold value (%) at which to generate a warning msg\n"
	"Restart bgp connection after limit is exceeded\n"
	"Restart interval in minutes\n"
	"Only give warning message when limit is exceeded\n"
	"Force checking all received routes not only accepted\n")

/* "neighbor accept-own" */
DEFPY (neighbor_accept_own,
       neighbor_accept_own_cmd,
       "[no$no] neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor accept-own",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Enable handling of self-originated VPN routes containing ACCEPT_OWN community\n")
{
	struct peer *peer;
	afi_t afi = bgp_node_afi(vty);
	safi_t safi = bgp_node_safi(vty);
	int ret;

	peer = peer_and_group_lookup_vty(vty, neighbor);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	if (no)
		ret = peer_af_flag_unset(peer, afi, safi, PEER_FLAG_ACCEPT_OWN);
	else
		ret = peer_af_flag_set(peer, afi, safi, PEER_FLAG_ACCEPT_OWN);

	return bgp_vty_return(vty, ret);
}

/* "neighbor soo" */
DEFPY (neighbor_soo,
       neighbor_soo_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor soo ASN:NN_OR_IP-ADDRESS:NN$soo",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Set the Site-of-Origin (SoO) extended community\n"
       "VPN extended community\n")
{
	struct peer *peer;
	afi_t afi = bgp_node_afi(vty);
	safi_t safi = bgp_node_safi(vty);
	struct ecommunity *ecomm_soo;

	peer = peer_and_group_lookup_vty(vty, neighbor);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	ecomm_soo = ecommunity_str2com(soo, ECOMMUNITY_SITE_ORIGIN, 0);
	if (!ecomm_soo) {
		vty_out(vty, "%% Malformed SoO extended community\n");
		return CMD_WARNING;
	}
	ecommunity_str(ecomm_soo);

	if (!ecommunity_match(peer->soo[afi][safi], ecomm_soo)) {
		ecommunity_free(&peer->soo[afi][safi]);
		peer->soo[afi][safi] = ecomm_soo;
		peer_af_flag_unset(peer, afi, safi, PEER_FLAG_SOO);
	} else {
		ecommunity_free(&ecomm_soo);
	}

	return bgp_vty_return(vty,
			      peer_af_flag_set(peer, afi, safi, PEER_FLAG_SOO));
}

DEFPY (no_neighbor_soo,
       no_neighbor_soo_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor soo [ASN:NN_OR_IP-ADDRESS:NN$soo]",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Set the Site-of-Origin (SoO) extended community\n"
       "VPN extended community\n")
{
	struct peer *peer;
	afi_t afi = bgp_node_afi(vty);
	safi_t safi = bgp_node_safi(vty);

	peer = peer_and_group_lookup_vty(vty, neighbor);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	ecommunity_free(&peer->soo[afi][safi]);

	return bgp_vty_return(
		vty, peer_af_flag_unset(peer, afi, safi, PEER_FLAG_SOO));
}

/* "neighbor allowas-in" */
DEFUN (neighbor_allowas_in,
       neighbor_allowas_in_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> allowas-in [<(1-10)|origin>]",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Accept as-path with my AS present in it\n"
       "Number of occurrences of AS number\n"
       "Only accept my AS in the as-path if the route was originated in my AS\n")
{
	int idx_peer = 1;
	int idx_number_origin = 3;
	int ret;
	int origin = 0;
	struct peer *peer;
	int allow_num = 0;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	if (argc <= idx_number_origin)
		allow_num = 3;
	else {
		if (argv[idx_number_origin]->type == WORD_TKN)
			origin = 1;
		else
			allow_num = atoi(argv[idx_number_origin]->arg);
	}

	ret = peer_allowas_in_set(peer, bgp_node_afi(vty), bgp_node_safi(vty),
				  allow_num, origin);

	return bgp_vty_return(vty, ret);
}

ALIAS_HIDDEN(
	neighbor_allowas_in, neighbor_allowas_in_hidden_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD> allowas-in [<(1-10)|origin>]",
	NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	"Accept as-path with my AS present in it\n"
	"Number of occurrences of AS number\n"
	"Only accept my AS in the as-path if the route was originated in my AS\n")

DEFUN (no_neighbor_allowas_in,
       no_neighbor_allowas_in_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> allowas-in [<(1-10)|origin>]",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "allow local ASN appears in aspath attribute\n"
       "Number of occurrences of AS number\n"
       "Only accept my AS in the as-path if the route was originated in my AS\n")
{
	int idx_peer = 2;
	int ret;
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	ret = peer_allowas_in_unset(peer, bgp_node_afi(vty),
				    bgp_node_safi(vty));

	return bgp_vty_return(vty, ret);
}

ALIAS_HIDDEN(
	no_neighbor_allowas_in, no_neighbor_allowas_in_hidden_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD> allowas-in [<(1-10)|origin>]",
	NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	"allow local ASN appears in aspath attribute\n"
	"Number of occurrences of AS number\n"
	"Only accept my AS in the as-path if the route was originated in my AS\n")

DEFUN (neighbor_ttl_security,
       neighbor_ttl_security_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> ttl-security hops (1-254)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP ttl-security parameters\n"
       "Specify the maximum number of hops to the BGP peer\n"
       "Number of hops to BGP peer\n")
{
	int idx_peer = 1;
	int idx_number = 4;
	struct peer *peer;
	int gtsm_hops;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	gtsm_hops = strtoul(argv[idx_number]->arg, NULL, 10);

	/*
	 * If 'neighbor swpX', then this is for directly connected peers,
	 * we should not accept a ttl-security hops value greater than 1.
	 */
	if (peer->conf_if && (gtsm_hops > BGP_GTSM_HOPS_CONNECTED)) {
		vty_out(vty,
			"%s is directly connected peer, hops cannot exceed 1\n",
			argv[idx_peer]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	return bgp_vty_return(vty, peer_ttl_security_hops_set(peer, gtsm_hops));
}

DEFUN (no_neighbor_ttl_security,
       no_neighbor_ttl_security_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> ttl-security hops (1-254)",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP ttl-security parameters\n"
       "Specify the maximum number of hops to the BGP peer\n"
       "Number of hops to BGP peer\n")
{
	int idx_peer = 2;
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	return bgp_vty_return(vty, peer_ttl_security_hops_unset(peer));
}

/* disable-addpath-rx */
DEFUN(neighbor_disable_addpath_rx,
      neighbor_disable_addpath_rx_cmd,
      "neighbor <A.B.C.D|X:X::X:X|WORD> disable-addpath-rx",
      NEIGHBOR_STR
      NEIGHBOR_ADDR_STR2
      "Do not accept additional paths\n")
{
	char *peer_str = argv[1]->arg;
	struct peer *peer;
	afi_t afi = bgp_node_afi(vty);
	safi_t safi = bgp_node_safi(vty);
	int ret;
	int action;

	peer = peer_and_group_lookup_vty(vty, peer_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	action = bgp_addpath_capability_action(peer->addpath_type[afi][safi], 0);

	ret = peer_af_flag_set_vty(vty, peer_str, afi, safi,
				   PEER_FLAG_DISABLE_ADDPATH_RX);

	bgp_capability_send(peer, afi, safi, CAPABILITY_CODE_ADDPATH, action);

	return ret;
}

DEFUN(no_neighbor_disable_addpath_rx,
      no_neighbor_disable_addpath_rx_cmd,
      "no neighbor <A.B.C.D|X:X::X:X|WORD> disable-addpath-rx",
      NO_STR
      NEIGHBOR_STR
      NEIGHBOR_ADDR_STR2
      "Do not accept additional paths\n")
{
	char *peer_str = argv[2]->arg;
	struct peer *peer;
	afi_t afi = bgp_node_afi(vty);
	safi_t safi = bgp_node_safi(vty);
	int ret;
	int action;

	peer = peer_and_group_lookup_vty(vty, peer_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	action = bgp_addpath_capability_action(peer->addpath_type[afi][safi], 0);

	ret = peer_af_flag_unset_vty(vty, peer_str, afi, safi,
				     PEER_FLAG_DISABLE_ADDPATH_RX);

	bgp_capability_send(peer, afi, safi, CAPABILITY_CODE_ADDPATH, action);

	return ret;
}

DEFUN (neighbor_addpath_tx_all_paths,
       neighbor_addpath_tx_all_paths_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> addpath-tx-all-paths",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Use addpath to advertise all paths to a neighbor\n")
{
	int idx_peer = 1;
	struct peer *peer;
	afi_t afi = bgp_node_afi(vty);
	safi_t safi = bgp_node_safi(vty);

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	bgp_addpath_set_peer_type(peer, afi, safi, BGP_ADDPATH_ALL, 0);

	return CMD_SUCCESS;
}

ALIAS_HIDDEN(neighbor_addpath_tx_all_paths,
	     neighbor_addpath_tx_all_paths_hidden_cmd,
	     "neighbor <A.B.C.D|X:X::X:X|WORD> addpath-tx-all-paths",
	     NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Use addpath to advertise all paths to a neighbor\n")

DEFUN (no_neighbor_addpath_tx_all_paths,
       no_neighbor_addpath_tx_all_paths_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> addpath-tx-all-paths",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Use addpath to advertise all paths to a neighbor\n")
{
	int idx_peer = 2;
	struct peer *peer;
	afi_t afi = bgp_node_afi(vty);
	safi_t safi = bgp_node_safi(vty);

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	if (peer->addpath_type[afi][safi] != BGP_ADDPATH_ALL) {
		vty_out(vty,
			"%% Peer not currently configured to transmit all paths.");
		return CMD_WARNING_CONFIG_FAILED;
	}

	bgp_addpath_set_peer_type(peer, afi, safi, BGP_ADDPATH_NONE, 0);

	return CMD_SUCCESS;
}

ALIAS_HIDDEN(no_neighbor_addpath_tx_all_paths,
	     no_neighbor_addpath_tx_all_paths_hidden_cmd,
	     "no neighbor <A.B.C.D|X:X::X:X|WORD> addpath-tx-all-paths",
	     NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Use addpath to advertise all paths to a neighbor\n")

DEFPY (neighbor_addpath_tx_best_selected_paths,
       neighbor_addpath_tx_best_selected_paths_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor addpath-tx-best-selected (1-6)$paths",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Use addpath to advertise best selected paths to a neighbor\n"
       "The number of best paths\n")
{
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, neighbor);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	bgp_addpath_set_peer_type(peer, bgp_node_afi(vty), bgp_node_safi(vty),
				  BGP_ADDPATH_BEST_SELECTED, paths);
	return CMD_SUCCESS;
}

DEFPY (no_neighbor_addpath_tx_best_selected_paths,
       no_neighbor_addpath_tx_best_selected_paths_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor addpath-tx-best-selected [(1-6)]",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Use addpath to advertise best selected paths to a neighbor\n"
       "The number of best paths\n")
{
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, neighbor);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	bgp_addpath_set_peer_type(peer, bgp_node_afi(vty), bgp_node_safi(vty),
				  BGP_ADDPATH_BEST_SELECTED, 0);
	return CMD_SUCCESS;
}

DEFUN (neighbor_addpath_tx_bestpath_per_as,
       neighbor_addpath_tx_bestpath_per_as_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> addpath-tx-bestpath-per-AS",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Use addpath to advertise the bestpath per each neighboring AS\n")
{
	int idx_peer = 1;
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	bgp_addpath_set_peer_type(peer, bgp_node_afi(vty), bgp_node_safi(vty),
				  BGP_ADDPATH_BEST_PER_AS, 0);

	return CMD_SUCCESS;
}

ALIAS_HIDDEN(neighbor_addpath_tx_bestpath_per_as,
	     neighbor_addpath_tx_bestpath_per_as_hidden_cmd,
	     "neighbor <A.B.C.D|X:X::X:X|WORD> addpath-tx-bestpath-per-AS",
	     NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Use addpath to advertise the bestpath per each neighboring AS\n")

DEFUN (no_neighbor_addpath_tx_bestpath_per_as,
       no_neighbor_addpath_tx_bestpath_per_as_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> addpath-tx-bestpath-per-AS",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Use addpath to advertise the bestpath per each neighboring AS\n")
{
	int idx_peer = 2;
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	if (peer->addpath_type[bgp_node_afi(vty)][bgp_node_safi(vty)]
	    != BGP_ADDPATH_BEST_PER_AS) {
		vty_out(vty,
			"%% Peer not currently configured to transmit all best path per as.");
		return CMD_WARNING_CONFIG_FAILED;
	}

	bgp_addpath_set_peer_type(peer, bgp_node_afi(vty), bgp_node_safi(vty),
				  BGP_ADDPATH_NONE, 0);

	return CMD_SUCCESS;
}

ALIAS_HIDDEN(no_neighbor_addpath_tx_bestpath_per_as,
	     no_neighbor_addpath_tx_bestpath_per_as_hidden_cmd,
	     "no neighbor <A.B.C.D|X:X::X:X|WORD> addpath-tx-bestpath-per-AS",
	     NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
	     "Use addpath to advertise the bestpath per each neighboring AS\n")

DEFPY(
	neighbor_aspath_loop_detection, neighbor_aspath_loop_detection_cmd,
	"neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor sender-as-path-loop-detection",
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Detect AS loops before sending to neighbor\n")
{
	return peer_flag_set_vty(vty, neighbor, PEER_FLAG_AS_LOOP_DETECTION);
}

DEFPY (neighbor_addpath_paths_limit,
       neighbor_addpath_paths_limit_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor addpath-rx-paths-limit (1-65535)$paths_limit",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Paths Limit for Addpath to receive from the peer\n"
       "Maximum number of paths\n")
{
	struct peer *peer;
	afi_t afi = bgp_node_afi(vty);
	safi_t safi = bgp_node_safi(vty);
	int ret;

	peer = peer_and_group_lookup_vty(vty, neighbor);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	ret = peer_af_flag_set_vty(vty, neighbor, afi, safi,
				   PEER_FLAG_ADDPATH_RX_PATHS_LIMIT);

	peer->addpath_paths_limit[afi][safi].send = paths_limit;

	bgp_capability_send(peer, afi, safi, CAPABILITY_CODE_PATHS_LIMIT,
			    CAPABILITY_ACTION_SET);

	return ret;
}

DEFPY (no_neighbor_addpath_paths_limit,
       no_neighbor_addpath_paths_limit_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor addpath-rx-paths-limit [(1-65535)]",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Paths Limit for Addpath to receive from the peer\n"
       "Maximum number of paths\n")
{
	struct peer *peer;
	afi_t afi = bgp_node_afi(vty);
	safi_t safi = bgp_node_safi(vty);
	int ret;

	peer = peer_and_group_lookup_vty(vty, neighbor);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	ret = peer_af_flag_unset_vty(vty, neighbor, afi, safi,
				     PEER_FLAG_ADDPATH_RX_PATHS_LIMIT);

	peer->addpath_paths_limit[afi][safi].send = 0;

	bgp_capability_send(peer, afi, safi, CAPABILITY_CODE_PATHS_LIMIT,
			    CAPABILITY_ACTION_SET);

	return ret;
}

DEFPY(
	no_neighbor_aspath_loop_detection,
	no_neighbor_aspath_loop_detection_cmd,
	"no neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor sender-as-path-loop-detection",
	NO_STR
	NEIGHBOR_STR
	NEIGHBOR_ADDR_STR2
	"Detect AS loops before sending to neighbor\n")
{
	return peer_flag_unset_vty(vty, neighbor, PEER_FLAG_AS_LOOP_DETECTION);
}

DEFPY(neighbor_path_attribute_discard,
      neighbor_path_attribute_discard_cmd,
      "neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor path-attribute discard (1-255)...",
      NEIGHBOR_STR
      NEIGHBOR_ADDR_STR2
      "Manipulate path attributes from incoming UPDATE messages\n"
      "Drop specified attributes from incoming UPDATE messages\n"
      "Attribute number\n")
{
	struct peer *peer;
	int idx = 0;
	char *discard_attrs = NULL;

	peer = peer_and_group_lookup_vty(vty, neighbor);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	argv_find(argv, argc, "(1-255)", &idx);
	if (idx)
		discard_attrs = argv_concat(argv, argc, idx);

	bgp_path_attribute_discard_vty(vty, peer, discard_attrs, true);

	XFREE(MTYPE_TMP, discard_attrs);

	return CMD_SUCCESS;
}

DEFPY(no_neighbor_path_attribute_discard,
      no_neighbor_path_attribute_discard_cmd,
      "no neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor path-attribute discard [(1-255)]",
      NO_STR
      NEIGHBOR_STR
      NEIGHBOR_ADDR_STR2
      "Manipulate path attributes from incoming UPDATE messages\n"
      "Drop specified attributes from incoming UPDATE messages\n"
      "Attribute number\n")
{
	struct peer *peer;
	int idx = 0;
	char *discard_attrs = NULL;

	peer = peer_and_group_lookup_vty(vty, neighbor);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	argv_find(argv, argc, "(1-255)", &idx);
	if (idx)
		discard_attrs = argv[idx]->arg;

	bgp_path_attribute_discard_vty(vty, peer, discard_attrs, false);

	XFREE(MTYPE_TMP, discard_attrs);

	return CMD_SUCCESS;
}

DEFPY(neighbor_path_attribute_treat_as_withdraw,
      neighbor_path_attribute_treat_as_withdraw_cmd,
      "neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor path-attribute treat-as-withdraw (1-255)...",
      NEIGHBOR_STR
      NEIGHBOR_ADDR_STR2
      "Manipulate path attributes from incoming UPDATE messages\n"
      "Treat-as-withdraw any incoming BGP UPDATE messages that contain the specified attribute\n"
      "Attribute number\n")
{
	struct peer *peer;
	int idx = 0;
	char *withdraw_attrs = NULL;

	peer = peer_and_group_lookup_vty(vty, neighbor);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	argv_find(argv, argc, "(1-255)", &idx);
	if (idx)
		withdraw_attrs = argv_concat(argv, argc, idx);

	bgp_path_attribute_withdraw_vty(vty, peer, withdraw_attrs, true);

	XFREE(MTYPE_TMP, withdraw_attrs);

	return CMD_SUCCESS;
}

DEFPY(no_neighbor_path_attribute_treat_as_withdraw,
      no_neighbor_path_attribute_treat_as_withdraw_cmd,
      "no neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor path-attribute treat-as-withdraw (1-255)...",
      NO_STR
      NEIGHBOR_STR
      NEIGHBOR_ADDR_STR2
      "Manipulate path attributes from incoming UPDATE messages\n"
      "Treat-as-withdraw any incoming BGP UPDATE messages that contain the specified attribute\n"
      "Attribute number\n")
{
	struct peer *peer;
	int idx = 0;
	char *withdraw_attrs = NULL;

	peer = peer_and_group_lookup_vty(vty, neighbor);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	argv_find(argv, argc, "(1-255)", &idx);
	if (idx)
		withdraw_attrs = argv_concat(argv, argc, idx);

	bgp_path_attribute_withdraw_vty(vty, peer, withdraw_attrs, false);

	XFREE(MTYPE_TMP, withdraw_attrs);

	return CMD_SUCCESS;
}

DEFPY(neighbor_damp,
      neighbor_damp_cmd,
      "neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor dampening [(1-45)$half [(1-20000)$reuse (1-20000)$suppress (1-255)$max]]",
      NEIGHBOR_STR
      NEIGHBOR_ADDR_STR2
      "Enable neighbor route-flap dampening\n"
      "Half-life time for the penalty\n"
      "Value to start reusing a route\n"
      "Value to start suppressing a route\n"
      "Maximum duration to suppress a stable route\n")
{
	struct peer *peer = peer_and_group_lookup_vty(vty, neighbor);

	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;
	if (!half)
		half = DEFAULT_HALF_LIFE;
	if (!reuse) {
		reuse = DEFAULT_REUSE;
		suppress = DEFAULT_SUPPRESS;
		max = half * 4;
	}
	if (suppress < reuse) {
		vty_out(vty, "Suppress value cannot be less than reuse value\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	bgp_peer_damp_enable(peer, bgp_node_afi(vty), bgp_node_safi(vty),
			     half * 60, reuse, suppress, max * 60);
	return CMD_SUCCESS;
}

DEFPY(no_neighbor_damp,
      no_neighbor_damp_cmd,
      "no neighbor <A.B.C.D|X:X::X:X|WORD>$neighbor dampening [HALF [REUSE SUPPRESS MAX]]",
      NO_STR
      NEIGHBOR_STR
      NEIGHBOR_ADDR_STR2
      "Enable neighbor route-flap dampening\n"
      "Half-life time for the penalty\n"
      "Value to start reusing a route\n"
      "Value to start suppressing a route\n"
      "Maximum duration to suppress a stable route\n")
{
	struct peer *peer = peer_and_group_lookup_vty(vty, neighbor);

	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;
	bgp_peer_damp_disable(peer, bgp_node_afi(vty), bgp_node_safi(vty));
	return CMD_SUCCESS;
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

static int set_ecom_list(struct vty *vty, int argc, struct cmd_token **argv,
			 struct ecommunity **list, bool is_rt6)
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

/*
 * v2vimport is true if we are handling a `import vrf ...` command
 */
static afi_t vpn_policy_getafi(struct vty *vty, struct bgp *bgp, bool v2vimport)
{
	afi_t afi;

	switch (vty->node) {
	case BGP_IPV4_NODE:
		afi = AFI_IP;
		break;
	case BGP_IPV6_NODE:
		afi = AFI_IP6;
		break;
	default:
		vty_out(vty,
			"%% context error: valid only in address-family <ipv4|ipv6> unicast block\n");
		return AFI_MAX;
	}

	if (!v2vimport) {
		if (CHECK_FLAG(bgp->af_flags[afi][SAFI_UNICAST],
			       BGP_CONFIG_VRF_TO_VRF_IMPORT)
		    || CHECK_FLAG(bgp->af_flags[afi][SAFI_UNICAST],
				  BGP_CONFIG_VRF_TO_VRF_EXPORT)) {
			vty_out(vty,
				"%% error: Please unconfigure import vrf commands before using vpn commands\n");
			return AFI_MAX;
		}
	} else {
		if (CHECK_FLAG(bgp->af_flags[afi][SAFI_UNICAST],
			       BGP_CONFIG_VRF_TO_MPLSVPN_EXPORT)
		    || CHECK_FLAG(bgp->af_flags[afi][SAFI_UNICAST],
				  BGP_CONFIG_MPLSVPN_TO_VRF_IMPORT)) {
			vty_out(vty,
				"%% error: Please unconfigure vpn to vrf commands before using import vrf commands\n");
			return AFI_MAX;
		}
	}
	return afi;
}

DEFPY (af_rd_vpn_export,
       af_rd_vpn_export_cmd,
       "[no] rd vpn export ASN:NN_OR_IP-ADDRESS:NN$rd_str",
       NO_STR
       "Specify route distinguisher\n"
       "Between current address-family and vpn\n"
       "For routes leaked from current address-family to vpn\n"
       "Route Distinguisher (<as-number>:<number> | <ip-address>:<number>)\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	struct prefix_rd prd;
	int ret;
	afi_t afi;
	int idx = 0;
	bool yes = true;

	if (argv_find(argv, argc, "no", &idx))
		yes = false;

	if (yes) {
		ret = str2prefix_rd(rd_str, &prd);
		if (!ret) {
			vty_out(vty, "%% Malformed rd\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	afi = vpn_policy_getafi(vty, bgp, false);
	if (afi == AFI_MAX)
		return CMD_WARNING_CONFIG_FAILED;

	/*
	 * pre-change: un-export vpn routes (vpn->vrf routes unaffected)
	 */
	vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, afi,
			   bgp_get_default(), bgp);

	if (yes) {
		bgp->vpn_policy[afi].tovpn_rd_pretty = XSTRDUP(MTYPE_BGP_NAME,
							       rd_str);
		bgp->vpn_policy[afi].tovpn_rd = prd;
		SET_FLAG(bgp->vpn_policy[afi].flags,
			 BGP_VPN_POLICY_TOVPN_RD_SET);
	} else {
		XFREE(MTYPE_BGP_NAME, bgp->vpn_policy[afi].tovpn_rd_pretty);
		UNSET_FLAG(bgp->vpn_policy[afi].flags,
			   BGP_VPN_POLICY_TOVPN_RD_SET);
	}

	/* post-change: re-export vpn routes */
	vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, afi,
			    bgp_get_default(), bgp);

	return CMD_SUCCESS;
}

ALIAS (af_rd_vpn_export,
       af_no_rd_vpn_export_cmd,
       "no rd vpn export",
       NO_STR
       "Specify route distinguisher\n"
       "Between current address-family and vpn\n"
       "For routes leaked from current address-family to vpn\n")

DEFPY(af_label_vpn_export_allocation_mode,
      af_label_vpn_export_allocation_mode_cmd,
      "[no$no] label vpn export allocation-mode <per-vrf$label_per_vrf|per-nexthop$label_per_nh>",
      NO_STR
      "label value for VRF\n"
      "Between current address-family and vpn\n"
      "For routes leaked from current address-family to vpn\n"
      "Label allocation mode\n"
      "Allocate one label for all BGP updates of the VRF\n"
      "Allocate a label per connected next-hop in the VRF\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	afi_t afi;
	bool old_per_nexthop, new_per_nexthop;

	afi = vpn_policy_getafi(vty, bgp, false);
	if (afi == AFI_MAX)
		return CMD_WARNING_CONFIG_FAILED;

	old_per_nexthop = !!CHECK_FLAG(bgp->vpn_policy[afi].flags,
				       BGP_VPN_POLICY_TOVPN_LABEL_PER_NEXTHOP);
	if (no) {
		if (old_per_nexthop == false && label_per_nh)
			return CMD_ERR_NO_MATCH;
		if (old_per_nexthop == true && label_per_vrf)
			return CMD_ERR_NO_MATCH;
		new_per_nexthop = false;
	} else {
		if (label_per_nh)
			new_per_nexthop = true;
		else
			new_per_nexthop = false;
	}

	/* no change */
	if (old_per_nexthop == new_per_nexthop)
		return CMD_SUCCESS;

	/*
	 * pre-change: un-export vpn routes (vpn->vrf routes unaffected)
	 */
	vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(),
			   bgp);

	if (new_per_nexthop)
		SET_FLAG(bgp->vpn_policy[afi].flags,
			 BGP_VPN_POLICY_TOVPN_LABEL_PER_NEXTHOP);
	else
		UNSET_FLAG(bgp->vpn_policy[afi].flags,
			   BGP_VPN_POLICY_TOVPN_LABEL_PER_NEXTHOP);

	/* post-change: re-export vpn routes */
	vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(),
			    bgp);

	hook_call(bgp_snmp_update_last_changed, bgp);
	return CMD_SUCCESS;
}

DEFPY (af_label_vpn_export,
       af_label_vpn_export_cmd,
       "[no] label vpn export <(0-1048575)$label_val|auto$label_auto>",
       NO_STR
       "label value for VRF\n"
       "Between current address-family and vpn\n"
       "For routes leaked from current address-family to vpn\n"
       "Label Value <0-1048575>\n"
       "Automatically assign a label\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	mpls_label_t label = (mpls_label_t)label_val;
	afi_t afi;
	int idx = 0;
	bool yes = true;

	if (argv_find(argv, argc, "no", &idx))
		yes = false;

	afi = vpn_policy_getafi(vty, bgp, false);
	if (afi == AFI_MAX)
		return CMD_WARNING_CONFIG_FAILED;

	if (yes) {
		if (label_auto && CHECK_FLAG(bgp->vpn_policy[afi].flags,
					     BGP_VPN_POLICY_TOVPN_LABEL_AUTO))
			/* no change */
			return CMD_SUCCESS;
		if (!label_auto && label == bgp->vpn_policy[afi].tovpn_label)
			/* no change */
			return CMD_SUCCESS;
	} else {
		if (label_auto && !CHECK_FLAG(bgp->vpn_policy[afi].flags,
					      BGP_VPN_POLICY_TOVPN_LABEL_AUTO))
			/* no match */
			return CMD_WARNING_CONFIG_FAILED;
		if (!label_auto && label_val &&
		    label != bgp->vpn_policy[afi].tovpn_label)
			/* no change */
			return CMD_WARNING_CONFIG_FAILED;
	}

	/*
	 * pre-change: un-export vpn routes (vpn->vrf routes unaffected)
	 */
	vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, afi,
			   bgp_get_default(), bgp);

	if (CHECK_FLAG(bgp->vpn_policy[afi].flags,
		       BGP_VPN_POLICY_TOVPN_LABEL_MANUAL_REG)) {
		bgp_zebra_release_label_range(bgp->vpn_policy[afi].tovpn_label,
					      bgp->vpn_policy[afi].tovpn_label);
		UNSET_FLAG(bgp->vpn_policy[afi].flags,
			   BGP_VPN_POLICY_TOVPN_LABEL_MANUAL_REG);

	} else if (CHECK_FLAG(bgp->vpn_policy[afi].flags,
			      BGP_VPN_POLICY_TOVPN_LABEL_AUTO)) {
		/* release any previous auto label */
		if (bgp->vpn_policy[afi].tovpn_label != MPLS_LABEL_NONE) {

			/*
			 * label has previously been automatically
			 * assigned by labelpool: release it
			 *
			 * NB if tovpn_label == MPLS_LABEL_NONE it
			 * means the automatic assignment is in flight
			 * and therefore the labelpool callback must
			 * detect that the auto label is not needed.
			 */

			bgp_lp_release(LP_TYPE_VRF,
				       &bgp->vpn_policy[afi],
				       bgp->vpn_policy[afi].tovpn_label);
		}
	}

	if (yes) {
		if (label_auto) {
			SET_FLAG(bgp->vpn_policy[afi].flags,
				 BGP_VPN_POLICY_TOVPN_LABEL_AUTO);
			/* fetch a label */
			bgp->vpn_policy[afi].tovpn_label = MPLS_LABEL_NONE;
		} else {
			bgp->vpn_policy[afi].tovpn_label = label;
			UNSET_FLAG(bgp->vpn_policy[afi].flags,
				   BGP_VPN_POLICY_TOVPN_LABEL_AUTO);
			if (bgp->vpn_policy[afi].tovpn_label >=
				    MPLS_LABEL_UNRESERVED_MIN &&
			    bgp_zebra_request_label_range(bgp->vpn_policy[afi]
								  .tovpn_label,
							  1, false))
				SET_FLAG(bgp->vpn_policy[afi].flags,
					 BGP_VPN_POLICY_TOVPN_LABEL_MANUAL_REG);
		}
	} else {
		UNSET_FLAG(bgp->vpn_policy[afi].flags,
			   BGP_VPN_POLICY_TOVPN_LABEL_AUTO);
		bgp->vpn_policy[afi].tovpn_label = MPLS_LABEL_NONE;
	}

	/* post-change: re-export vpn routes */
	vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, afi,
			    bgp_get_default(), bgp);

	hook_call(bgp_snmp_update_last_changed, bgp);
	return CMD_SUCCESS;
}

DEFPY (af_sid_vpn_export,
       af_sid_vpn_export_cmd,
       "[no] sid vpn export <(1-1048575)$sid_idx|auto$sid_auto>",
       NO_STR
       "sid value for VRF\n"
       "Between current address-family and vpn\n"
       "For routes leaked from current address-family to vpn\n"
       "Sid allocation index\n"
       "Automatically assign a label\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	afi_t afi;
	int debug = 0;
	int idx = 0;
	bool yes = true;

	if (argv_find(argv, argc, "no", &idx))
		yes = false;
	debug = (BGP_DEBUG(vpn, VPN_LEAK_TO_VRF) |
		 BGP_DEBUG(vpn, VPN_LEAK_FROM_VRF));

	afi = vpn_policy_getafi(vty, bgp, false);
	if (afi == AFI_MAX)
		return CMD_WARNING_CONFIG_FAILED;

	if (!yes) {
		/* when SID is not set, do nothing */
		if ((bgp->vpn_policy[afi].tovpn_sid_index == 0) &&
		    !CHECK_FLAG(bgp->vpn_policy[afi].flags,
				BGP_VPN_POLICY_TOVPN_SID_AUTO))
			return CMD_SUCCESS;

		/* pre-change */
		vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, afi,
				   bgp_get_default(), bgp);
		bgp->vpn_policy[afi].tovpn_sid_index = 0;
		UNSET_FLAG(bgp->vpn_policy[afi].flags,
			   BGP_VPN_POLICY_TOVPN_SID_AUTO);

		/* post-change */
		vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, afi,
				    bgp_get_default(), bgp);

		return CMD_SUCCESS;
	}

	if (bgp->tovpn_sid_index != 0 ||
	    CHECK_FLAG(bgp->vrf_flags, BGP_VRF_TOVPN_SID_AUTO)) {
		vty_out(vty,
			"per-vrf sid and per-af sid are mutually exclusive\n"
			"Failed: per-vrf sid is configured. Remove per-vrf sid before configuring per-af sid\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* skip when it's already configured */
	if ((sid_idx != 0 && bgp->vpn_policy[afi].tovpn_sid_index != 0)
	    || (sid_auto && CHECK_FLAG(bgp->vpn_policy[afi].flags,
				       BGP_VPN_POLICY_TOVPN_SID_AUTO)))
		return CMD_SUCCESS;

	/*
	 * mode change between sid_idx and sid_auto isn't supported.
	 * user must negate sid vpn export when they want to change the mode
	 */
	if ((sid_auto && bgp->vpn_policy[afi].tovpn_sid_index != 0)
	    || (sid_idx != 0 && CHECK_FLAG(bgp->vpn_policy[afi].flags,
					   BGP_VPN_POLICY_TOVPN_SID_AUTO))) {
		vty_out(vty, "it's already configured as %s.\n",
			sid_auto ? "auto-mode" : "idx-mode");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* pre-change */
	vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, afi,
			   bgp_get_default(), bgp);

	if (sid_auto) {
		/* SID allocation auto-mode */
		if (debug)
			zlog_debug("%s: auto sid alloc.", __func__);
		SET_FLAG(bgp->vpn_policy[afi].flags,
			 BGP_VPN_POLICY_TOVPN_SID_AUTO);
	} else if (sid_idx != 0) {
		/* SID allocation index-mode */
		if (debug)
			zlog_debug("%s: idx %ld sid alloc.", __func__, sid_idx);
		bgp->vpn_policy[afi].tovpn_sid_index = sid_idx;
	}

	/* post-change */
	vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, afi,
			    bgp_get_default(), bgp);
	return CMD_SUCCESS;
}

DEFPY (bgp_sid_vpn_export,
       bgp_sid_vpn_export_cmd,
       "[no] sid vpn per-vrf export <(1-1048575)$sid_idx|auto$sid_auto>",
       NO_STR
       "sid value for VRF\n"
       "Between current vrf and vpn\n"
       "sid per-VRF (both IPv4 and IPv6 address families)\n"
       "For routes leaked from current vrf to vpn\n"
       "Sid allocation index\n"
       "Automatically assign a label\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int debug;

	debug = (BGP_DEBUG(vpn, VPN_LEAK_TO_VRF) |
		 BGP_DEBUG(vpn, VPN_LEAK_FROM_VRF));

	if (no) {
		/* when per-VRF SID is not set, do nothing */
		if (bgp->tovpn_sid_index == 0 &&
		    !CHECK_FLAG(bgp->vrf_flags, BGP_VRF_TOVPN_SID_AUTO))
			return CMD_SUCCESS;

		sid_idx = 0;
		sid_auto = false;
		bgp->tovpn_sid_index = 0;
		UNSET_FLAG(bgp->vrf_flags, BGP_VRF_TOVPN_SID_AUTO);
	}

	if (bgp->vpn_policy[AFI_IP].tovpn_sid_index != 0 ||
	    CHECK_FLAG(bgp->vpn_policy[AFI_IP].flags,
		       BGP_VPN_POLICY_TOVPN_SID_AUTO) ||
	    bgp->vpn_policy[AFI_IP6].tovpn_sid_index != 0 ||
	    CHECK_FLAG(bgp->vpn_policy[AFI_IP6].flags,
		       BGP_VPN_POLICY_TOVPN_SID_AUTO)) {
		vty_out(vty,
			"per-vrf sid and per-af sid are mutually exclusive\n"
			"Failed: per-af sid is configured. Remove per-af sid before configuring per-vrf sid\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* skip when it's already configured */
	if ((sid_idx != 0 && bgp->tovpn_sid_index != 0) ||
	    (sid_auto && CHECK_FLAG(bgp->vrf_flags, BGP_VRF_TOVPN_SID_AUTO)))
		return CMD_SUCCESS;

	/*
	 * mode change between sid_idx and sid_auto isn't supported.
	 * user must negate sid vpn export when they want to change the mode
	 */
	if ((sid_auto && bgp->tovpn_sid_index != 0) ||
	    (sid_idx != 0 &&
	     CHECK_FLAG(bgp->vrf_flags, BGP_VRF_TOVPN_SID_AUTO))) {
		vty_out(vty, "it's already configured as %s.\n",
			sid_auto ? "auto-mode" : "idx-mode");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* pre-change */
	vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, AFI_IP, bgp_get_default(),
			   bgp);
	vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, AFI_IP6, bgp_get_default(),
			   bgp);

	if (sid_auto) {
		/* SID allocation auto-mode */
		if (debug)
			zlog_debug("%s: auto per-vrf sid alloc.", __func__);
		SET_FLAG(bgp->vrf_flags, BGP_VRF_TOVPN_SID_AUTO);
	} else if (sid_idx != 0) {
		/* SID allocation index-mode */
		if (debug)
			zlog_debug("%s: idx %ld per-vrf sid alloc.", __func__,
				   sid_idx);
		bgp->tovpn_sid_index = sid_idx;
	}

	/* post-change */
	vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, AFI_IP, bgp_get_default(),
			    bgp);
	vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, AFI_IP6,
			    bgp_get_default(), bgp);

	return CMD_SUCCESS;
}

ALIAS (af_label_vpn_export,
       af_no_label_vpn_export_cmd,
       "no label vpn export",
       NO_STR
       "label value for VRF\n"
       "Between current address-family and vpn\n"
       "For routes leaked from current address-family to vpn\n")

ALIAS (bgp_sid_vpn_export,
       no_bgp_sid_vpn_export_cmd,
       "no$no sid vpn per-vrf export",
       NO_STR
       "sid value for VRF\n"
       "Between current vrf and vpn\n"
       "sid per-VRF (both IPv4 and IPv6 address families)\n"
       "For routes leaked from current vrf to vpn\n")

DEFPY (af_nexthop_vpn_export,
       af_nexthop_vpn_export_cmd,
       "[no] nexthop vpn export [<A.B.C.D|X:X::X:X>$nexthop_su]",
       NO_STR
       "Specify next hop to use for VRF advertised prefixes\n"
       "Between current address-family and vpn\n"
       "For routes leaked from current address-family to vpn\n"
       "IPv4 prefix\n"
       "IPv6 prefix\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	afi_t afi;
	struct prefix p;

	if (!no) {
		if (!nexthop_su) {
			vty_out(vty, "%% Nexthop required\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		if (!sockunion2hostprefix(nexthop_su, &p))
			return CMD_WARNING_CONFIG_FAILED;
	}

	afi = vpn_policy_getafi(vty, bgp, false);
	if (afi == AFI_MAX)
		return CMD_WARNING_CONFIG_FAILED;

	/*
	 * pre-change: un-export vpn routes (vpn->vrf routes unaffected)
	 */
	vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, afi,
			   bgp_get_default(), bgp);

	if (!no) {
		bgp->vpn_policy[afi].tovpn_nexthop = p;
		SET_FLAG(bgp->vpn_policy[afi].flags,
			 BGP_VPN_POLICY_TOVPN_NEXTHOP_SET);
	} else {
		UNSET_FLAG(bgp->vpn_policy[afi].flags,
			   BGP_VPN_POLICY_TOVPN_NEXTHOP_SET);
	}

	/* post-change: re-export vpn routes */
	vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, afi,
			    bgp_get_default(), bgp);

	return CMD_SUCCESS;
}

static int vpn_policy_getdirs(struct vty *vty, const char *dstr, int *dodir)
{
	if (!strcmp(dstr, "import")) {
		dodir[BGP_VPN_POLICY_DIR_FROMVPN] = 1;
	} else if (!strcmp(dstr, "export")) {
		dodir[BGP_VPN_POLICY_DIR_TOVPN] = 1;
	} else if (!strcmp(dstr, "both")) {
		dodir[BGP_VPN_POLICY_DIR_FROMVPN] = 1;
		dodir[BGP_VPN_POLICY_DIR_TOVPN] = 1;
	} else {
		vty_out(vty, "%% direction parse error\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	return CMD_SUCCESS;
}

DEFPY (af_rt_vpn_imexport,
       af_rt_vpn_imexport_cmd,
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
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int ret;
	struct ecommunity *ecom = NULL;
	int dodir[BGP_VPN_POLICY_DIR_MAX] = {0};
	enum vpn_policy_direction dir;
	afi_t afi;
	int idx = 0;
	bool yes = true;

	if (argv_find(argv, argc, "no", &idx))
		yes = false;

	afi = vpn_policy_getafi(vty, bgp, false);
	if (afi == AFI_MAX)
		return CMD_WARNING_CONFIG_FAILED;

	ret = vpn_policy_getdirs(vty, direction_str, dodir);
	if (ret != CMD_SUCCESS)
		return ret;

	if (yes) {
		if (!argv_find(argv, argc, "RTLIST", &idx)) {
			vty_out(vty, "%% Missing RTLIST\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		ret = set_ecom_list(vty, argc - idx, argv + idx, &ecom, false);
		if (ret != CMD_SUCCESS) {
			return ret;
		}
	}

	for (dir = 0; dir < BGP_VPN_POLICY_DIR_MAX; ++dir) {
		if (!dodir[dir])
			continue;

		vpn_leak_prechange(dir, afi, bgp_get_default(), bgp);

		if (yes) {
			if (bgp->vpn_policy[afi].rtlist[dir])
				ecommunity_free(
						&bgp->vpn_policy[afi].rtlist[dir]);
			bgp->vpn_policy[afi].rtlist[dir] =
				ecommunity_dup(ecom);
		} else {
			if (bgp->vpn_policy[afi].rtlist[dir])
				ecommunity_free(
						&bgp->vpn_policy[afi].rtlist[dir]);
			bgp->vpn_policy[afi].rtlist[dir] = NULL;
		}

		vpn_leak_postchange(dir, afi, bgp_get_default(), bgp);
	}

	if (ecom)
		ecommunity_free(&ecom);

	return CMD_SUCCESS;
}

ALIAS (af_rt_vpn_imexport,
       af_no_rt_vpn_imexport_cmd,
       "no <rt|route-target> vpn <import|export|both>$direction_str",
       NO_STR
       "Specify route target list\n"
       "Specify route target list\n"
       "Between current address-family and vpn\n"
       "For routes leaked from vpn to current address-family\n"
       "For routes leaked from current address-family to vpn\n"
       "both import and export\n")

DEFPY (af_route_map_vpn_imexport,
       af_route_map_vpn_imexport_cmd,
/* future: "route-map <vpn|evpn|vrf NAME> <import|export> RMAP" */
       "[no] route-map vpn <import|export>$direction_str RMAP$rmap_str",
       NO_STR
       "Specify route map\n"
       "Between current address-family and vpn\n"
       "For routes leaked from vpn to current address-family\n"
       "For routes leaked from current address-family to vpn\n"
       "name of route-map\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int ret;
	int dodir[BGP_VPN_POLICY_DIR_MAX] = {0};
	enum vpn_policy_direction dir;
	afi_t afi;
	int idx = 0;
	bool yes = true;

	if (argv_find(argv, argc, "no", &idx))
		yes = false;

	afi = vpn_policy_getafi(vty, bgp, false);
	if (afi == AFI_MAX)
		return CMD_WARNING_CONFIG_FAILED;

	ret = vpn_policy_getdirs(vty, direction_str, dodir);
	if (ret != CMD_SUCCESS)
		return ret;

	for (dir = 0; dir < BGP_VPN_POLICY_DIR_MAX; ++dir) {
		if (!dodir[dir])
			continue;

		vpn_leak_prechange(dir, afi, bgp_get_default(), bgp);

		if (yes) {
			if (bgp->vpn_policy[afi].rmap_name[dir])
				XFREE(MTYPE_ROUTE_MAP_NAME,
				      bgp->vpn_policy[afi].rmap_name[dir]);
			bgp->vpn_policy[afi].rmap_name[dir] = XSTRDUP(
								      MTYPE_ROUTE_MAP_NAME, rmap_str);
			bgp->vpn_policy[afi].rmap[dir] =
				route_map_lookup_warn_noexist(vty, rmap_str);
			if (!bgp->vpn_policy[afi].rmap[dir])
				return CMD_SUCCESS;
		} else {
			if (bgp->vpn_policy[afi].rmap_name[dir])
				XFREE(MTYPE_ROUTE_MAP_NAME,
				      bgp->vpn_policy[afi].rmap_name[dir]);
			bgp->vpn_policy[afi].rmap_name[dir] = NULL;
			bgp->vpn_policy[afi].rmap[dir] = NULL;
		}

		vpn_leak_postchange(dir, afi, bgp_get_default(), bgp);
	}

	return CMD_SUCCESS;
}

ALIAS (af_route_map_vpn_imexport,
       af_no_route_map_vpn_imexport_cmd,
       "no route-map vpn <import|export>$direction_str",
       NO_STR
       "Specify route map\n"
       "Between current address-family and vpn\n"
       "For routes leaked from vpn to current address-family\n"
       "For routes leaked from current address-family to vpn\n")

DEFPY(af_import_vrf_route_map, af_import_vrf_route_map_cmd,
      "import vrf route-map RMAP$rmap_str",
      "Import routes from another VRF\n"
      "Vrf routes being filtered\n"
      "Specify route map\n"
      "name of route-map\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	enum vpn_policy_direction dir = BGP_VPN_POLICY_DIR_FROMVPN;
	afi_t afi;
	struct bgp *bgp_default;

	afi = vpn_policy_getafi(vty, bgp, true);
	if (afi == AFI_MAX)
		return CMD_WARNING_CONFIG_FAILED;

	bgp_default = bgp_get_default();
	if (!bgp_default) {
		int32_t ret;
		as_t as = AS_UNSPECIFIED;

		/* Auto-create with AS_UNSPECIFIED, to be filled in later */
		ret = bgp_get_vty(&bgp_default, &as, NULL,
				  BGP_INSTANCE_TYPE_DEFAULT, NULL,
				  ASNOTATION_UNDEFINED);

		if (ret) {
			vty_out(vty,
				"VRF default is not configured as a bgp instance\n");
			return CMD_WARNING;
		}

		SET_FLAG(bgp_default->flags, BGP_FLAG_INSTANCE_HIDDEN);
	}

	vpn_leak_prechange(dir, afi, bgp_get_default(), bgp);

	if (bgp->vpn_policy[afi].rmap_name[dir])
		XFREE(MTYPE_ROUTE_MAP_NAME,
		      bgp->vpn_policy[afi].rmap_name[dir]);
	bgp->vpn_policy[afi].rmap_name[dir] =
		XSTRDUP(MTYPE_ROUTE_MAP_NAME, rmap_str);
	bgp->vpn_policy[afi].rmap[dir] =
		route_map_lookup_warn_noexist(vty, rmap_str);
	if (!bgp->vpn_policy[afi].rmap[dir])
		return CMD_SUCCESS;

	SET_FLAG(bgp->af_flags[afi][SAFI_UNICAST],
		 BGP_CONFIG_VRF_TO_VRF_IMPORT);

	vpn_leak_postchange(dir, afi, bgp_get_default(), bgp);

	return CMD_SUCCESS;
}

DEFPY(af_no_import_vrf_route_map, af_no_import_vrf_route_map_cmd,
      "no import vrf route-map [RMAP$rmap_str]",
      NO_STR
      "Import routes from another VRF\n"
      "Vrf routes being filtered\n"
      "Specify route map\n"
      "name of route-map\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	enum vpn_policy_direction dir = BGP_VPN_POLICY_DIR_FROMVPN;
	afi_t afi;

	afi = vpn_policy_getafi(vty, bgp, true);
	if (afi == AFI_MAX)
		return CMD_WARNING_CONFIG_FAILED;

	vpn_leak_prechange(dir, afi, bgp_get_default(), bgp);

	if (bgp->vpn_policy[afi].rmap_name[dir])
		XFREE(MTYPE_ROUTE_MAP_NAME,
		      bgp->vpn_policy[afi].rmap_name[dir]);
	bgp->vpn_policy[afi].rmap_name[dir] = NULL;
	bgp->vpn_policy[afi].rmap[dir] = NULL;

	if (bgp->vpn_policy[afi].import_vrf->count == 0)
		UNSET_FLAG(bgp->af_flags[afi][SAFI_UNICAST],
			   BGP_CONFIG_VRF_TO_VRF_IMPORT);

	vpn_leak_postchange(dir, afi, bgp_get_default(), bgp);

	return CMD_SUCCESS;
}

DEFPY(bgp_imexport_vrf, bgp_imexport_vrf_cmd,
      "[no] import vrf VIEWVRFNAME$import_name",
      NO_STR
      "Import routes from another VRF\n"
      "VRF to import from\n"
      "The name of the VRF\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	struct listnode *node;
	struct bgp *vrf_bgp, *bgp_default;
	int32_t ret = 0;
	as_t as = bgp->as;
	bool remove = false;
	int32_t idx = 0;
	char *vname;
	enum bgp_instance_type bgp_type = BGP_INSTANCE_TYPE_VRF;
	safi_t safi;
	afi_t afi;

	if (import_name == NULL) {
		vty_out(vty, "%% Missing import name\n");
		return CMD_WARNING;
	}

	if (strcmp(import_name, "route-map") == 0) {
		vty_out(vty, "%% Must include route-map name\n");
		return CMD_WARNING;
	}

	if (argv_find(argv, argc, "no", &idx))
		remove = true;

	afi = vpn_policy_getafi(vty, bgp, true);
	if (afi == AFI_MAX)
		return CMD_WARNING_CONFIG_FAILED;

	safi = bgp_node_safi(vty);

	if (((BGP_INSTANCE_TYPE_DEFAULT == bgp->inst_type)
	     && (strcmp(import_name, VRF_DEFAULT_NAME) == 0))
	    || (bgp->name && (strcmp(import_name, bgp->name) == 0))) {
		vty_out(vty, "%% Cannot %s vrf %s into itself\n",
			remove ? "unimport" : "import", import_name);
		return CMD_WARNING;
	}

	bgp_default = bgp_get_default();
	if (!bgp_default) {
		as = AS_UNSPECIFIED;

		/* Auto-create with AS_UNSPECIFIED, to be filled in later */
		ret = bgp_get_vty(&bgp_default, &as, NULL,
				  BGP_INSTANCE_TYPE_DEFAULT, NULL,
				  ASNOTATION_UNDEFINED);

		if (ret) {
			vty_out(vty,
				"VRF default is not configured as a bgp instance\n");
			return CMD_WARNING;
		}

		SET_FLAG(bgp_default->flags, BGP_FLAG_INSTANCE_HIDDEN);
	}

	vrf_bgp = bgp_lookup_by_name(import_name);
	if (!vrf_bgp) {
		if (strcmp(import_name, VRF_DEFAULT_NAME) == 0) {
			vrf_bgp = bgp_default;
		} else {
			as = AS_UNSPECIFIED;

			/* Auto-create with AS_UNSPECIFIED, fill in later */
			ret = bgp_get_vty(&vrf_bgp, &as, import_name, bgp_type,
					  NULL, ASNOTATION_UNDEFINED);
			if (ret) {
				vty_out(vty,
					"VRF %s is not configured as a bgp instance\n",
					import_name);
				return CMD_WARNING;
			}

			SET_FLAG(vrf_bgp->flags, BGP_FLAG_INSTANCE_HIDDEN);

			/* Auto created VRF instances should be marked
			 * properly, otherwise we have a state after bgpd
			 * restart where VRF instance has default VRF's ASN.
			 */
			SET_FLAG(vrf_bgp->vrf_flags, BGP_VRF_AUTO);
		}
	}

	if (remove) {
		vrf_unimport_from_vrf(bgp, vrf_bgp, afi, safi);
	} else {
		/* Already importing from "import_vrf"? */
		for (ALL_LIST_ELEMENTS_RO(bgp->vpn_policy[afi].import_vrf, node,
					  vname)) {
			if (strcmp(vname, import_name) == 0)
				return CMD_WARNING;
		}

		vrf_import_from_vrf(bgp, vrf_bgp, afi, safi);
	}

	return CMD_SUCCESS;
}

/* This command is valid only in a bgp vrf instance or the default instance */
DEFPY (bgp_imexport_vpn,
       bgp_imexport_vpn_cmd,
       "[no] <import|export>$direction_str vpn",
       NO_STR
       "Import routes to this address-family\n"
       "Export routes from this address-family\n"
       "to/from default instance VPN RIB\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int previous_state;
	afi_t afi;
	safi_t safi;
	int idx = 0;
	bool yes = true;
	int flag;
	enum vpn_policy_direction dir;
	struct bgp *bgp_default = bgp_get_default();

	if (argv_find(argv, argc, "no", &idx))
		yes = false;

	if (BGP_INSTANCE_TYPE_VRF != bgp->inst_type &&
		BGP_INSTANCE_TYPE_DEFAULT != bgp->inst_type) {

		vty_out(vty, "%% import|export vpn valid only for bgp vrf or default instance\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	afi = bgp_node_afi(vty);
	safi = bgp_node_safi(vty);
	if ((SAFI_UNICAST != safi) || ((AFI_IP != afi) && (AFI_IP6 != afi))) {
		vty_out(vty, "%% import|export vpn valid only for unicast ipv4|ipv6\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (!strcmp(direction_str, "import")) {
		flag = BGP_CONFIG_MPLSVPN_TO_VRF_IMPORT;
		dir = BGP_VPN_POLICY_DIR_FROMVPN;
	} else if (!strcmp(direction_str, "export")) {
		flag = BGP_CONFIG_VRF_TO_MPLSVPN_EXPORT;
		dir = BGP_VPN_POLICY_DIR_TOVPN;
	} else {
		vty_out(vty, "%% unknown direction %s\n", direction_str);
		return CMD_WARNING_CONFIG_FAILED;
	}

	previous_state = CHECK_FLAG(bgp->af_flags[afi][safi], flag);

	if (yes) {
		SET_FLAG(bgp->af_flags[afi][safi], flag);
		if (!previous_state) {
			/* trigger export current vrf */
			vpn_leak_postchange(dir, afi, bgp_default, bgp);
		}
	} else {
		if (previous_state) {
			/* trigger un-export current vrf */
			vpn_leak_prechange(dir, afi, bgp_default, bgp);
		}
		UNSET_FLAG(bgp->af_flags[afi][safi], flag);
		if (previous_state && bgp_default &&
		    !CHECK_FLAG(bgp_default->af_flags[afi][SAFI_MPLS_VPN],
				BGP_VPNVX_RETAIN_ROUTE_TARGET_ALL))
			vpn_leak_no_retain(bgp, bgp_default, afi);
	}

	hook_call(bgp_snmp_init_stats, bgp);

	return CMD_SUCCESS;
}

DEFPY (af_routetarget_import,
       af_routetarget_import_cmd,
       "[no] <rt|route-target|route-target6|rt6> redirect import RTLIST...",
       NO_STR
       "Specify route target list\n"
       "Specify route target list\n"
       "Specify route target list\n"
       "Specify route target list\n"
       "Flow-spec redirect type route target\n"
       "Import routes to this address-family\n"
       "Space separated route target list (A.B.C.D:MN|EF:OPQR|GHJK:MN|IPV6:MN)\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int ret;
	struct ecommunity *ecom = NULL;
	afi_t afi;
	int idx = 0, idx_unused = 0;
	bool yes = true;
	bool rt6 = false;

	if (argv_find(argv, argc, "no", &idx))
		yes = false;

	if (argv_find(argv, argc, "rt6", &idx_unused) ||
	    argv_find(argv, argc, "route-target6", &idx_unused))
		rt6 = true;

	afi = vpn_policy_getafi(vty, bgp, false);
	if (afi == AFI_MAX)
		return CMD_WARNING_CONFIG_FAILED;

	if (rt6 && afi != AFI_IP6)
		return CMD_WARNING_CONFIG_FAILED;

	if (yes) {
		if (!argv_find(argv, argc, "RTLIST", &idx)) {
			vty_out(vty, "%% Missing RTLIST\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		ret = set_ecom_list(vty, argc - idx, argv + idx, &ecom, rt6);
		if (ret != CMD_SUCCESS)
			return ret;
	}

	if (yes) {
		if (bgp->vpn_policy[afi].import_redirect_rtlist)
			ecommunity_free(&bgp->vpn_policy[afi]
					.import_redirect_rtlist);
		bgp->vpn_policy[afi].import_redirect_rtlist =
			ecommunity_dup(ecom);
	} else {
		if (bgp->vpn_policy[afi].import_redirect_rtlist)
			ecommunity_free(&bgp->vpn_policy[afi]
					.import_redirect_rtlist);
		bgp->vpn_policy[afi].import_redirect_rtlist = NULL;
	}

	if (ecom)
		ecommunity_free(&ecom);

	return CMD_SUCCESS;
}

DEFUN_NOSH (address_family_ipv4_safi,
	address_family_ipv4_safi_cmd,
	"address-family ipv4 [<unicast|multicast|vpn|labeled-unicast|flowspec>]",
	"Enter Address Family command mode\n"
	BGP_AF_STR
	BGP_SAFI_WITH_LABEL_HELP_STR)
{

	if (argc == 3) {
		VTY_DECLVAR_CONTEXT(bgp, bgp);
		safi_t safi = bgp_vty_safi_from_str(argv[2]->text);
		if (bgp->inst_type != BGP_INSTANCE_TYPE_DEFAULT
		    && safi != SAFI_UNICAST && safi != SAFI_MULTICAST
		    && safi != SAFI_EVPN) {
			vty_out(vty,
				"Only Unicast/Multicast/EVPN SAFIs supported in non-core instances.\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		vty->node = bgp_node_type(AFI_IP, safi);
	} else
		vty->node = BGP_IPV4_NODE;

	return CMD_SUCCESS;
}

DEFUN_NOSH (address_family_ipv6_safi,
	address_family_ipv6_safi_cmd,
	"address-family ipv6 [<unicast|multicast|vpn|labeled-unicast|flowspec>]",
	"Enter Address Family command mode\n"
	BGP_AF_STR
	BGP_SAFI_WITH_LABEL_HELP_STR)
{
	if (argc == 3) {
		VTY_DECLVAR_CONTEXT(bgp, bgp);
		safi_t safi = bgp_vty_safi_from_str(argv[2]->text);
		if (bgp->inst_type != BGP_INSTANCE_TYPE_DEFAULT
		    && safi != SAFI_UNICAST && safi != SAFI_MULTICAST
		    && safi != SAFI_EVPN) {
			vty_out(vty,
				"Only Unicast/Multicast/EVPN SAFIs supported in non-core instances.\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		vty->node = bgp_node_type(AFI_IP6, safi);
	} else
		vty->node = BGP_IPV6_NODE;

	return CMD_SUCCESS;
}

#ifdef KEEP_OLD_VPN_COMMANDS
DEFUN_NOSH (address_family_vpnv4,
       address_family_vpnv4_cmd,
       "address-family vpnv4 [unicast]",
       "Enter Address Family command mode\n"
       BGP_AF_STR
       BGP_AF_MODIFIER_STR)
{
	vty->node = BGP_VPNV4_NODE;
	return CMD_SUCCESS;
}

DEFUN_NOSH (address_family_vpnv6,
       address_family_vpnv6_cmd,
       "address-family vpnv6 [unicast]",
       "Enter Address Family command mode\n"
       BGP_AF_STR
       BGP_AF_MODIFIER_STR)
{
	vty->node = BGP_VPNV6_NODE;
	return CMD_SUCCESS;
}
#endif /* KEEP_OLD_VPN_COMMANDS */

DEFUN_NOSH (address_family_evpn,
       address_family_evpn_cmd,
       "address-family l2vpn evpn",
       "Enter Address Family command mode\n"
       BGP_AF_STR
       BGP_AF_MODIFIER_STR)
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	vty->node = BGP_EVPN_NODE;
	return CMD_SUCCESS;
}

DEFUN_NOSH (bgp_segment_routing_srv6,
            bgp_segment_routing_srv6_cmd,
            "segment-routing srv6",
            "Segment-Routing configuration\n"
            "Segment-Routing SRv6 configuration\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	bgp->srv6_enabled = true;
	vty->node = BGP_SRV6_NODE;
	return CMD_SUCCESS;
}

DEFUN (no_bgp_segment_routing_srv6,
       no_bgp_segment_routing_srv6_cmd,
       "no segment-routing srv6",
       NO_STR
       "Segment-Routing configuration\n"
       "Segment-Routing SRv6 configuration\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	if (strlen(bgp->srv6_locator_name) > 0)
		if (bgp_srv6_locator_unset(bgp) < 0)
			return CMD_WARNING_CONFIG_FAILED;

	bgp->srv6_enabled = false;
	return CMD_SUCCESS;
}

DEFPY (bgp_srv6_locator,
       bgp_srv6_locator_cmd,
       "locator NAME$name",
       "Specify SRv6 locator\n"
       "Specify SRv6 locator\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int ret;

	if (strlen(bgp->srv6_locator_name) > 0
	    && strcmp(name, bgp->srv6_locator_name) != 0) {
		vty_out(vty, "srv6 locator is already configured\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	snprintf(bgp->srv6_locator_name,
		 sizeof(bgp->srv6_locator_name), "%s", name);

	ret = bgp_zebra_srv6_manager_get_locator(name);
	if (ret < 0)
		return CMD_WARNING_CONFIG_FAILED;

	return CMD_SUCCESS;
}

DEFPY (no_bgp_srv6_locator,
       no_bgp_srv6_locator_cmd,
       "no locator NAME$name",
       NO_STR
       "Specify SRv6 locator\n"
       "Specify SRv6 locator\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	/* when locator isn't configured, do nothing */
	if (strlen(bgp->srv6_locator_name) < 1)
		return CMD_SUCCESS;

	/* name validation */
	if (strcmp(name, bgp->srv6_locator_name) != 0) {
		vty_out(vty, "%% No srv6 locator is configured\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* unset locator */
	if (bgp_srv6_locator_unset(bgp) < 0)
		return CMD_WARNING_CONFIG_FAILED;

	return CMD_SUCCESS;
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
	}

	return CMD_SUCCESS;
}

DEFUN_NOSH (exit_address_family,
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
	    || vty->node == BGP_FLOWSPECV6_NODE)
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

	match.family = afi2family(afi);
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

/* one clear bgp command to rule them all */
DEFUN (clear_ip_bgp_all,
       clear_ip_bgp_all_cmd,
       "clear [ip] bgp [<view|vrf> VIEWVRFNAME] [<ipv4|ipv6|l2vpn> [<unicast|multicast|vpn|labeled-unicast|flowspec|evpn>]] <*|A.B.C.D$neighbor|X:X::X:X$neighbor|WORD$neighbor|ASNUM|external|peer-group PGNAME> [<soft [<in|out>]|in [prefix-filter]|out|message-stats|capabilities>]",
       CLEAR_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       BGP_AFI_HELP_STR
       BGP_AF_STR
       BGP_SAFI_WITH_LABEL_HELP_STR
       BGP_AF_MODIFIER_STR
       "Clear all peers\n"
       "BGP IPv4 neighbor to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "BGP neighbor on interface to clear\n"
       "Clear peers with the AS number in plain or dotted format\n"
       "Clear all external peers\n"
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       BGP_SOFT_STR
       BGP_SOFT_IN_STR
       BGP_SOFT_OUT_STR
       BGP_SOFT_IN_STR
       "Push out prefix-list ORF and do inbound soft reconfig\n"
       BGP_SOFT_OUT_STR
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
		clr_type = BGP_CLEAR_SOFT_NONE;

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
		if (!CHECK_FLAG(peer->flags, PEER_FLAG_CONFIG_NODE))
			continue;
		(*peers_cfgd)++;
		if (peer_established(peer->connection))
			(*peers_estbd)++;
	}
}

static void print_bgp_vrfs(struct bgp *bgp, struct vty *vty, json_object *json,
			   const char *type)
{
	int peers_cfg, peers_estb;

	calc_peers_cfgd_estbd(bgp, &peers_cfg, &peers_estb);

	if (json) {
		int64_t vrf_id_ui = (bgp->vrf_id == VRF_UNKNOWN)
					    ? -1
					    : (int64_t)bgp->vrf_id;
		json_object_string_add(json, "type", type);
		json_object_int_add(json, "vrfId", vrf_id_ui);
		json_object_string_addf(json, "routerId", "%pI4",
					&bgp->router_id);
		json_object_int_add(json, "numConfiguredPeers", peers_cfg);
		json_object_int_add(json, "numEstablishedPeers", peers_estb);
		json_object_int_add(json, "l3vni", bgp->l3vni);
		json_object_string_addf(json, "rmac", "%pEA", &bgp->rmac);
		json_object_string_add(
			json, "interface",
			ifindex2ifname(bgp->l3vni_svi_ifindex, bgp->vrf_id));
	}
}

static int show_bgp_vrfs_detail_common(struct vty *vty, struct bgp *bgp,
				       json_object *json, const char *name,
				       const char *type, bool use_vrf)
{
	int peers_cfg, peers_estb;

	calc_peers_cfgd_estbd(bgp, &peers_cfg, &peers_estb);

	if (use_vrf) {
		if (json) {
			print_bgp_vrfs(bgp, vty, json, type);
		} else {
			vty_out(vty, "BGP instance %s VRF id %d\n",
				bgp->name_pretty,
				bgp->vrf_id == VRF_UNKNOWN ? -1
							   : (int)bgp->vrf_id);
			vty_out(vty, "Router Id %pI4\n", &bgp->router_id);
			vty_out(vty,
				"Num Configured Peers %d, Established %d\n",
				peers_cfg, peers_estb);
			if (bgp->l3vni) {
				vty_out(vty,
					"L3VNI %u, L3VNI-SVI %s, Router MAC %pEA\n",
					bgp->l3vni,
					ifindex2ifname(bgp->l3vni_svi_ifindex,
						       bgp->vrf_id),
					&bgp->rmac);
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
		const char *name;

		/* Skip Views. */
		if (bgp->inst_type == BGP_INSTANCE_TYPE_VIEW)
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
			name = VRF_DEFAULT_NAME;
			type = "DFLT";
		} else {
			name = bgp->name;
			type = "VRF";
		}

		show_bgp_vrfs_detail_common(vty, bgp, json_vrf, name, type,
					    false);

		if (uj)
			json_object_object_add(json_vrfs, name, json_vrf);
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

	vty_out(vty, "addr: %pI4, count: %d\n", &tip->addr, tip->refcnt);
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
		vty_out(vty, "%ld compiled regexes, using %s of memory\n",
			count, mtype_memstr(memstrbuf, sizeof(memstrbuf),
					    count * sizeof(regex_t)));
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
		if (peer_established(peer->connection))
			json_object_string_add(json_peer, "lastResetDueTo",
					       "AFI/SAFI Not Negotiated");
		else
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
		if (peer_established(peer->connection))
			vty_out(vty, "  AFI/SAFI Not Negotiated\n");
		else
			bgp_show_peer_reset(vty, peer, NULL,
					    false);
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
 * sure `Desc` is the lastest column to show because it can contain
 * whitespaces and the whole output will be tricky.
 */
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

			if (!CHECK_FLAG(peer->flags, PEER_FLAG_CONFIG_NODE))
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

			if (!CHECK_FLAG(peer->flags, PEER_FLAG_CONFIG_NODE))
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
		if (!CHECK_FLAG(peer->flags, PEER_FLAG_CONFIG_NODE))
			continue;

		if (!peer->afc[afi][safi])
			continue;

		if (!count) {
			unsigned long ents;
			char memstrbuf[MTYPE_MEMSTR_LEN];
			int64_t vrf_id_ui;

			vrf_id_ui = (bgp->vrf_id == VRF_UNKNOWN)
					    ? -1
					    : (int64_t)bgp->vrf_id;

			/* Usage summary and header */
			if (use_json) {
				json_object_string_addf(json, "routerId",
							"%pI4",
							&bgp->router_id);
				asn_asn2json(json, "as", bgp->as,
					     bgp->asnotation);
				json_object_int_add(json, "vrfId", vrf_id_ui);
				json_object_string_add(
					json, "vrfName",
					(bgp->inst_type
					 == BGP_INSTANCE_TYPE_DEFAULT)
						? VRF_DEFAULT_NAME
						: bgp->name);
			} else {
				vty_out(vty,
					"BGP router identifier %pI4, local AS number %s %s vrf-id %d",
					&bgp->router_id, bgp->as_pretty,
					bgp->name_pretty,
					bgp->vrf_id == VRF_UNKNOWN
						? -1
						: (int)bgp->vrf_id);
				vty_out(vty, "\n");
			}

			if (bgp_update_delay_configured(bgp)) {
				if (use_json) {
					json_object_int_add(
						json, "updateDelayLimit",
						bgp->v_update_delay);

					if (bgp->v_update_delay
					    != bgp->v_establish_wait)
						json_object_int_add(
							json,
							"updateDelayEstablishWait",
							bgp->v_establish_wait);

					if (bgp_update_delay_active(bgp)) {
						json_object_string_add(
							json,
							"updateDelayFirstNeighbor",
							bgp->update_delay_begin_time);
						json_object_boolean_true_add(
							json,
							"updateDelayInProgress");
					} else {
						if (bgp->update_delay_over) {
							json_object_string_add(
								json,
								"updateDelayFirstNeighbor",
								bgp->update_delay_begin_time);
							json_object_string_add(
								json,
								"updateDelayBestpathResumed",
								bgp->update_delay_end_time);
							json_object_string_add(
								json,
								"updateDelayZebraUpdateResume",
								bgp->update_delay_zebra_resume_time);
							json_object_string_add(
								json,
								"updateDelayPeerUpdateResume",
								bgp->update_delay_peers_resume_time);
						}
					}
				} else {
					vty_out(vty,
						"Read-only mode update-delay limit: %d seconds\n",
						bgp->v_update_delay);
					if (bgp->v_update_delay
					    != bgp->v_establish_wait)
						vty_out(vty,
							"                   Establish wait: %d seconds\n",
							bgp->v_establish_wait);

					if (bgp_update_delay_active(bgp)) {
						vty_out(vty,
							"  First neighbor established: %s\n",
							bgp->update_delay_begin_time);
						vty_out(vty,
							"  Delay in progress\n");
					} else {
						if (bgp->update_delay_over) {
							vty_out(vty,
								"  First neighbor established: %s\n",
								bgp->update_delay_begin_time);
							vty_out(vty,
								"          Best-paths resumed: %s\n",
								bgp->update_delay_end_time);
							vty_out(vty,
								"        zebra update resumed: %s\n",
								bgp->update_delay_zebra_resume_time);
							vty_out(vty,
								"        peers update resumed: %s\n",
								bgp->update_delay_peers_resume_time);
						}
					}
				}
			}

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

				ents = bgp_table_count(bgp->rib[afi][safi]);
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

					ents = bgp_table_count(
						bgp->rib[afi][safi]);
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
			else if (peer->connection->su.sa.sa_family == AF_INET6)
				json_object_string_add(json_peer, "idType",
						       "ipv6");
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
				/* Make sure `Desc` column is the lastest in
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

	if (use_json && is_wildcard)
		vty_out(vty, "{\n");
	if (afi_wildcard)
		afi = 1; /* AFI_IP */
	while (afi < AFI_MAX) {
		if (safi_wildcard)
			safi = 1; /* SAFI_UNICAST */
		while (safi < SAFI_MAX) {
			if (bgp_afi_safi_peer_exists(bgp, afi, safi)) {
				nbr_output = true;

				if (is_wildcard) {
					/*
					 * So limit output to those afi/safi
					 * pairs that
					 * actualy have something interesting in
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

	if (!json)
		vty_out(vty, "\n    Remote GR Mode: ");

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
		vty_out(vty, "%s", mode);
}

static void bgp_show_neighbor_graceful_restart_local_mode(struct vty *vty,
							  struct peer *p,
							  json_object *json)
{
	const char *mode = "Invalid";

	if (!json)
		vty_out(vty, "    Local GR Mode: ");

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
		vty_out(vty, "%s", mode);
}

static void bgp_show_neighbor_graceful_restart_capability_per_afi_safi(
	struct vty *vty, struct peer *peer, json_object *json)
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

			if (peer->connection->t_gr_stale != NULL) {
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
				json_object_int_add(json_timer,
						    "selectionDeferralTimer",
						    peer->bgp->stalepath_time);
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
		} else {
			vty_out(vty, "      Timers:\n");
			vty_out(vty,
				"        Configured Stale Path Time(sec): %u\n",
				peer->bgp->stalepath_time);

			if (peer->connection->t_gr_stale != NULL)
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

		if (p->connection->t_gr_restart != NULL)
			json_object_int_add(json_timer, "restartTimerRemaining",
					    event_timer_remain_second(
						    p->connection->t_gr_restart));

		json_object_object_add(json, "timers", json_timer);
	} else {

		vty_out(vty, "    Timers:\n");
		vty_out(vty, "      Configured Restart Time(sec): %u\n",
			p->bgp->restart_time);

		vty_out(vty, "      Received Restart Time(sec): %u\n",
			p->v_gr_restart);
		vty_out(vty, "      Configured LLGR Stale Path Time(sec): %u\n",
			p->bgp->llgr_stale_time);
		if (p->connection->t_gr_restart != NULL)
			vty_out(vty, "      Restart Time Remaining(sec): %ld\n",
				event_timer_remain_second(
					p->connection->t_gr_restart));
		if (p->connection->t_gr_restart != NULL) {
			vty_out(vty, "      Restart Time Remaining(sec): %ld\n",
				event_timer_remain_second(
					p->connection->t_gr_restart));
		}
	}
}

static void bgp_show_peer_gr_status(struct vty *vty, struct peer *p,
				    json_object *json)
{
	char dn_flag[2] = {0};
	/* '*' + v6 address of neighbor */
	char neighborAddr[INET6_ADDRSTRLEN + 1] = {0};

	if (!p->conf_if && peer_dynamic_neighbor(p))
		dn_flag[0] = '*';

	if (p->conf_if) {
		if (json)
			json_object_string_addf(json, "neighborAddr", "%pSU",
						&p->connection->su);
		else
			vty_out(vty, "BGP neighbor on %s: %pSU\n", p->conf_if,
				&p->connection->su);
	} else {
		snprintf(neighborAddr, sizeof(neighborAddr), "%s%s", dn_flag,
			 p->host);

		if (json)
			json_object_string_add(json, "neighborAddr",
					       neighborAddr);
		else
			vty_out(vty, "BGP neighbor is %s\n", neighborAddr);
	}

	/* more gr info in new format */
	BGP_SHOW_PEER_GR_CAPABILITY(vty, p, json);
}

static void bgp_show_peer_afi(struct vty *vty, struct peer *p, afi_t afi,
			      safi_t safi, bool use_json,
			      json_object *json_neigh)
{
	struct bgp_filter *filter;
	struct peer_af *paf;
	char orf_pfx_name[BUFSIZ];
	int orf_pfx_count;
	json_object *json_af = NULL;
	json_object *json_prefA = NULL;
	json_object *json_addr = NULL;
	json_object *json_advmap = NULL;

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

		snprintf(orf_pfx_name, sizeof(orf_pfx_name), "%s.%d.%d",
			 p->host, afi, safi);
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

		if (CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_NEXTHOP_SELF)
		    || CHECK_FLAG(p->af_flags[afi][safi],
				  PEER_FLAG_FORCE_NEXTHOP_SELF))
			json_object_boolean_true_add(json_addr,
						     "routerAlwaysNextHop");
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
		if (CHECK_FLAG(p->af_flags[afi][safi], PEER_FLAG_SEND_COMMUNITY)
		    || CHECK_FLAG(p->af_flags[afi][safi],
				  PEER_FLAG_SEND_EXT_COMMUNITY)) {
			if (CHECK_FLAG(p->af_flags[afi][safi],
				       PEER_FLAG_SEND_COMMUNITY)
			    && CHECK_FLAG(p->af_flags[afi][safi],
					  PEER_FLAG_SEND_EXT_COMMUNITY))
				json_object_string_add(json_addr,
						       "commAttriSentToNbr",
						       "extendedAndStandard");
			else if (CHECK_FLAG(p->af_flags[afi][safi],
					    PEER_FLAG_SEND_EXT_COMMUNITY))
				json_object_string_add(json_addr,
						       "commAttriSentToNbr",
						       "extended");
			else
				json_object_string_add(json_addr,
						       "commAttriSentToNbr",
						       "standard");
		}
		if (CHECK_FLAG(p->af_flags[afi][safi],
			       PEER_FLAG_DEFAULT_ORIGINATE)) {
			if (p->default_rmap[afi][safi].name)
				json_object_string_add(
					json_addr, "defaultRouteMap",
					p->default_rmap[afi][safi].name);

			if (paf && PAF_SUBGRP(paf)
			    && CHECK_FLAG(PAF_SUBGRP(paf)->sflags,
					  SUBGRP_STATUS_DEFAULT_ORIGINATE))
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
				    p->pcount[afi][safi]);
		if (paf && PAF_SUBGRP(paf))
			json_object_int_add(json_addr, "sentPrefixCounter",
						(PAF_SUBGRP(paf))->scount);

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

		snprintf(orf_pfx_name, sizeof(orf_pfx_name), "%s.%d.%d",
			 p->host, afi, safi);
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
				vty_out(vty,
					"  Local AS allowed in path, %d occurrences\n",
					p->allowas_in[afi][safi]);
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
			if (paf && PAF_SUBGRP(paf)
			    && CHECK_FLAG(PAF_SUBGRP(paf)->sflags,
					  SUBGRP_STATUS_DEFAULT_ORIGINATE))
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

		/* Receive prefix count */
		vty_out(vty, "  %u accepted prefixes\n",
			p->pcount[afi][safi]);

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

static void bgp_show_peer(struct vty *vty, struct peer *p, bool use_json,
			  json_object *json)
{
	struct bgp *bgp;
	char timebuf[BGP_UPTIME_LEN];
	char dn_flag[2];
	afi_t afi;
	safi_t safi;
	uint16_t i;
	uint8_t *msg;
	json_object *json_neigh = NULL;
	time_t epoch_tbuf;
	uint32_t sync_tcp_mss;

	bgp = p->bgp;

	if (use_json)
		json_neigh = json_object_new_object();

	memset(dn_flag, '\0', sizeof(dn_flag));
	if (!p->conf_if && peer_dynamic_neighbor(p))
		dn_flag[0] = '*';

	if (!use_json) {
		if (p->conf_if) /* Configured interface name. */
			vty_out(vty, "BGP neighbor on %s: %pSU, ", p->conf_if,
				&p->connection->su);
		else /* Configured IP address. */
			vty_out(vty, "BGP neighbor is %s%s, ", dn_flag,
				p->host);
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
	if ((p->as == p->local_as) || (CHECK_FLAG(p->as_type, AS_INTERNAL))) {
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
	} else if (p->as || (p->as_type == AS_EXTERNAL)) {
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
		json_object_string_add(json_neigh, "localRole",
				       bgp_get_name_by_role(p->local_role));
		json_object_string_add(json_neigh, "remoteRole",
				       bgp_get_name_by_role(p->remote_role));
	} else {
		vty_out(vty, "  Local Role: %s\n",
			bgp_get_name_by_role(p->local_role));
		vty_out(vty, "  Remote Role: %s\n",
			bgp_get_name_by_role(p->remote_role));
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
		json_object_string_add(json_neigh, "bgpState",
				       lookup_msg(bgp_status_msg,
						  p->connection->status, NULL));

		if (peer_established(p->connection)) {
			time_t uptime;

			uptime = monotime(NULL);
			uptime -= p->uptime;
			epoch_tbuf = time(NULL) - uptime;

			json_object_int_add(json_neigh, "bgpTimerUpMsec",
					    uptime * 1000);
			json_object_string_add(json_neigh, "bgpTimerUpString",
					       peer_uptime(p->uptime, timebuf,
							   BGP_UPTIME_LEN, 0,
							   NULL));
			json_object_int_add(json_neigh,
					    "bgpTimerUpEstablishedEpoch",
					    epoch_tbuf);
		} else if (p->connection->status == Active) {
			if (CHECK_FLAG(p->flags, PEER_FLAG_PASSIVE))
				json_object_string_add(json_neigh, "bgpStateIs",
						       "passive");
			else if (CHECK_FLAG(p->sflags, PEER_STATUS_NSF_WAIT))
				json_object_string_add(json_neigh, "bgpStateIs",
						       "passiveNSF");
		}

		/* read timer */
		time_t uptime;
		struct tm tm;

		uptime = monotime(NULL);
		uptime -= p->readtime;
		gmtime_r(&uptime, &tm);

		json_object_int_add(json_neigh, "bgpTimerLastRead",
				    (tm.tm_sec * 1000) + (tm.tm_min * 60000)
					    + (tm.tm_hour * 3600000));

		uptime = monotime(NULL);
		uptime -= p->last_write;
		gmtime_r(&uptime, &tm);

		json_object_int_add(json_neigh, "bgpTimerLastWrite",
				    (tm.tm_sec * 1000) + (tm.tm_min * 60000)
					    + (tm.tm_hour * 3600000));

		uptime = monotime(NULL);
		uptime -= p->update_time;
		gmtime_r(&uptime, &tm);

		json_object_int_add(json_neigh, "bgpInUpdateElapsedTimeMsecs",
				    (tm.tm_sec * 1000) + (tm.tm_min * 60000)
					    + (tm.tm_hour * 3600000));

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
		vty_out(vty, "  BGP state = %s",
			lookup_msg(bgp_status_msg, p->connection->status, NULL));

		if (peer_established(p->connection))
			vty_out(vty, ", up for %8s",
				peer_uptime(p->uptime, timebuf, BGP_UPTIME_LEN,
					    0, NULL));
		else if (p->connection->status == Active) {
			if (CHECK_FLAG(p->flags, PEER_FLAG_PASSIVE))
				vty_out(vty, " (passive)");
			else if (CHECK_FLAG(p->sflags, PEER_STATUS_NSF_WAIT))
				vty_out(vty, " (NSF passive)");
		}
		vty_out(vty, "\n");

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

			/* Graceful Restart */
			if (CHECK_FLAG(p->cap, PEER_CAP_RESTART_RCV) ||
			    CHECK_FLAG(p->cap, PEER_CAP_RESTART_ADV)) {
				if (CHECK_FLAG(p->cap, PEER_CAP_RESTART_ADV) &&
				    CHECK_FLAG(p->cap, PEER_CAP_RESTART_RCV))
					json_object_string_add(
						json_cap, "gracefulRestart",
						"advertisedAndReceived");
				else if (CHECK_FLAG(p->cap,
						    PEER_CAP_RESTART_ADV))
					json_object_string_add(
						json_cap,
						"gracefulRestartCapability",
						"advertised");
				else if (CHECK_FLAG(p->cap,
						    PEER_CAP_RESTART_RCV))
					json_object_string_add(
						json_cap,
						"gracefulRestartCapability",
						"received");

				if (CHECK_FLAG(p->cap, PEER_CAP_RESTART_RCV)) {
					int restart_af_count = 0;
					json_object *json_restart = NULL;
					json_restart = json_object_new_object();

					json_object_int_add(
						json_cap,
						"gracefulRestartRemoteTimerMsecs",
						p->v_gr_restart * 1000);

					FOREACH_AFI_SAFI (afi, safi) {
						if (CHECK_FLAG(
							    p->af_cap[afi]
								     [safi],
							    PEER_CAP_RESTART_AF_RCV)) {
							json_object *json_sub =
								NULL;
							json_sub =
								json_object_new_object();

							if (CHECK_FLAG(
								    p->af_cap
									    [afi]
									    [safi],
								    PEER_CAP_RESTART_AF_PRESERVE_RCV))
								json_object_boolean_true_add(
									json_sub,
									"preserved");
							restart_af_count++;
							json_object_object_add(
								json_restart,
								get_afi_safi_str(
									afi,
									safi,
									true),
								json_sub);
						}
					}
					if (!restart_af_count) {
						json_object_string_add(
							json_cap,
							"addressFamiliesByPeer",
							"none");
						json_object_free(json_restart);
					} else
						json_object_object_add(
							json_cap,
							"addressFamiliesByPeer",
							json_restart);
				}
			}
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
					int restart_af_count = 0;

					vty_out(vty,
						"      Remote Restart timer is %d seconds\n",
						p->v_gr_restart);
					vty_out(vty,
						"      Address families by peer:\n        ");

					FOREACH_AFI_SAFI (afi, safi)
						if (CHECK_FLAG(
							    p->af_cap[afi]
								     [safi],
							    PEER_CAP_RESTART_AF_RCV)) {
							vty_out(vty, "%s%s(%s)",
								restart_af_count
									? ", "
									: "",
								get_afi_safi_str(
									afi,
									safi,
									false),
								CHECK_FLAG(
									p->af_cap
										[afi]
										[safi],
									PEER_CAP_RESTART_AF_PRESERVE_RCV)
									? "preserved"
									: "not preserved");
							restart_af_count++;
						}
					if (!restart_af_count)
						vty_out(vty, "none");
					vty_out(vty, "\n");
				}
			} /* Graceful Restart */
		}
	}

	/* graceful restart information */
	json_object *json_grace = NULL;
	json_object *json_grace_send = NULL;
	json_object *json_grace_recv = NULL;
	int eor_send_af_count = 0;
	int eor_receive_af_count = 0;

	if (use_json) {
		json_grace = json_object_new_object();
		json_grace_send = json_object_new_object();
		json_grace_recv = json_object_new_object();

		if ((peer_established(p->connection)) &&
		    CHECK_FLAG(p->cap, PEER_CAP_RESTART_RCV)) {
			FOREACH_AFI_SAFI (afi, safi) {
				if (CHECK_FLAG(p->af_sflags[afi][safi],
					       PEER_STATUS_EOR_SEND)) {
					json_object_boolean_true_add(
						json_grace_send,
						get_afi_safi_str(afi, safi,
								 true));
					eor_send_af_count++;
				}
			}
			FOREACH_AFI_SAFI (afi, safi) {
				if (CHECK_FLAG(p->af_sflags[afi][safi],
					       PEER_STATUS_EOR_RECEIVED)) {
					json_object_boolean_true_add(
						json_grace_recv,
						get_afi_safi_str(afi, safi,
								 true));
					eor_receive_af_count++;
				}
			}
		}
		json_object_object_add(json_grace, "endOfRibSend",
				       json_grace_send);
		json_object_object_add(json_grace, "endOfRibRecv",
				       json_grace_recv);


		if (p->connection->t_gr_restart)
			json_object_int_add(json_grace,
					    "gracefulRestartTimerMsecs",
					    event_timer_remain_second(
						    p->connection->t_gr_restart) *
						    1000);

		if (p->connection->t_gr_stale)
			json_object_int_add(json_grace,
					    "gracefulStalepathTimerMsecs",
					    event_timer_remain_second(
						    p->connection->t_gr_stale) *
						    1000);
		/* more gr info in new format */
		BGP_SHOW_PEER_GR_CAPABILITY(vty, p, json_grace);
		json_object_object_add(json_neigh, "gracefulRestartInfo",
				       json_grace);
	} else {
		vty_out(vty, "  Graceful restart information:\n");
		if ((peer_established(p->connection)) &&
		    CHECK_FLAG(p->cap, PEER_CAP_RESTART_RCV)) {
			vty_out(vty, "    End-of-RIB send: ");
			FOREACH_AFI_SAFI (afi, safi) {
				if (CHECK_FLAG(p->af_sflags[afi][safi],
					       PEER_STATUS_EOR_SEND)) {
					vty_out(vty, "%s%s",
						eor_send_af_count ? ", " : "",
						get_afi_safi_str(afi, safi,
								 false));
					eor_send_af_count++;
				}
			}
			vty_out(vty, "\n");
			vty_out(vty, "    End-of-RIB received: ");
			FOREACH_AFI_SAFI (afi, safi) {
				if (CHECK_FLAG(p->af_sflags[afi][safi],
					       PEER_STATUS_EOR_RECEIVED)) {
					vty_out(vty, "%s%s",
						eor_receive_af_count ? ", "
								     : "",
						get_afi_safi_str(afi, safi,
								 false));
					eor_receive_af_count++;
				}
			}
			vty_out(vty, "\n");
		}

		if (p->connection->t_gr_restart)
			vty_out(vty,
				"    The remaining time of restart timer is %ld\n",
				event_timer_remain_second(
					p->connection->t_gr_restart));

		if (p->connection->t_gr_stale)
			vty_out(vty,
				"    The remaining time of stalepath timer is %ld\n",
				event_timer_remain_second(
					p->connection->t_gr_stale));

		/* more gr info in new format */
		BGP_SHOW_PEER_GR_CAPABILITY(vty, p, NULL);
	}

	if (use_json) {
		json_object *json_stat = NULL;
		json_stat = json_object_new_object();
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
		vty_out(vty, "    Total:         %10u %10u\n",
			(uint32_t)PEER_TOTAL_TX(p), (uint32_t)PEER_TOTAL_RX(p));
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
	} else {
		/* advertisement-interval */
		vty_out(vty,
			"  Minimum time between advertisement runs is %d seconds\n",
			p->v_routeadv);

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

	if (!p->last_reset) {
		if (use_json)
			json_object_string_add(json_neigh, "lastReset",
					       "never");
		else
			vty_out(vty, "  Last reset never\n");
	} else {
		if (use_json) {
			time_t uptime;
			struct tm tm;

			uptime = monotime(NULL);
			uptime -= p->resettime;
			gmtime_r(&uptime, &tm);

			json_object_int_add(json_neigh, "lastResetTimerMsecs",
					    (tm.tm_sec * 1000)
						    + (tm.tm_min * 60000)
						    + (tm.tm_hour * 3600000));
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

		if (p->connection->t_pmax_restart) {
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
	if (p->su_local) {
		if (use_json) {
			json_object_string_addf(json_neigh, "hostLocal", "%pSU",
						p->su_local);
			json_object_int_add(json_neigh, "portLocal",
					    ntohs(p->su_local->sin.sin_port));
		} else
			vty_out(vty, "Local host: %pSU, Local port: %d\n",
				p->su_local, ntohs(p->su_local->sin.sin_port));
	} else {
		if (use_json) {
			json_object_string_add(json_neigh, "hostLocal",
					       "Unknown");
			json_object_int_add(json_neigh, "portLocal", -1);
		}
	}

	/* Remote address. */
	if (p->su_remote) {
		if (use_json) {
			json_object_string_addf(json_neigh, "hostForeign",
						"%pSU", p->su_remote);
			json_object_int_add(json_neigh, "portForeign",
					    ntohs(p->su_remote->sin.sin_port));
		} else
			vty_out(vty, "Foreign host: %pSU, Foreign port: %d\n",
				p->su_remote,
				ntohs(p->su_remote->sin.sin_port));
	} else {
		if (use_json) {
			json_object_string_add(json_neigh, "hostForeign",
					       "Unknown");
			json_object_int_add(json_neigh, "portForeign", -1);
		}
	}

	/* Nexthop display. */
	if (p->su_local) {
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
		if (p->connection->t_start)
			json_object_int_add(json_neigh,
					    "nextStartTimerDueInMsecs",
					    event_timer_remain_second(
						    p->connection->t_start) *
						    1000);
		if (p->connection->t_connect)
			json_object_int_add(json_neigh,
					    "nextConnectTimerDueInMsecs",
					    event_timer_remain_second(
						    p->connection->t_connect) *
						    1000);
		if (p->connection->t_routeadv) {
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

		if (p->connection->t_read)
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
		if (p->connection->t_start)
			vty_out(vty, "Next start timer due in %ld seconds\n",
				event_timer_remain_second(
					p->connection->t_start));
		if (p->connection->t_connect)
			vty_out(vty, "Next connect timer due in %ld seconds\n",
				event_timer_remain_second(
					p->connection->t_connect));
		if (p->connection->t_routeadv)
			vty_out(vty,
				"MRAI (interval %u) timer expires in %ld seconds\n",
				p->v_routeadv,
				event_timer_remain_second(
					p->connection->t_routeadv));
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

static int bgp_show_neighbor_graceful_restart(struct vty *vty, struct bgp *bgp,
					      enum show_type type,
					      union sockunion *su,
					      const char *conf_if, afi_t afi,
					      json_object *json)
{
	struct listnode *node, *nnode;
	struct peer *peer;
	bool found = false;
	safi_t safi = SAFI_UNICAST;
	json_object *json_neighbor = NULL;

	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {

		if (!CHECK_FLAG(peer->flags, PEER_FLAG_CONFIG_NODE))
			continue;

		if ((peer->afc[afi][safi]) == 0)
			continue;

		if (json)
			json_neighbor = json_object_new_object();

		if (type == show_all) {
			bgp_show_peer_gr_status(vty, peer, json_neighbor);

			if (json)
				json_object_object_add(json, peer->host,
						       json_neighbor);

		} else if (type == show_peer) {
			if (conf_if) {
				if ((peer->conf_if
				     && !strcmp(peer->conf_if, conf_if))
				    || (peer->hostname
					&& !strcmp(peer->hostname, conf_if))) {
					found = true;
					bgp_show_peer_gr_status(vty, peer,
								json_neighbor);
				}
			} else {
				if (sockunion_same(&peer->connection->su, su)) {
					found = true;
					bgp_show_peer_gr_status(vty, peer,
								json_neighbor);
				}
			}
			if (json) {
				if (found)
					json_object_object_add(json, peer->host,
							       json_neighbor);
				else
					json_object_free(json_neighbor);
			}
		}

		if (found)
			break;
	}

	if (type == show_peer && !found) {
		if (json)
			json_object_boolean_true_add(json, "bgpNoSuchNeighbor");
		else
			vty_out(vty, "%% No such neighbor\n");
	}

	if (!json)
		vty_out(vty, "\n");

	return CMD_SUCCESS;
}

static int bgp_show_neighbor(struct vty *vty, struct bgp *bgp,
			     enum show_type type, union sockunion *su,
			     const char *conf_if, bool use_json,
			     json_object *json)
{
	struct listnode *node, *nnode;
	struct peer *peer;
	int find = 0;
	bool nbr_output = false;
	afi_t afi = AFI_MAX;
	safi_t safi = SAFI_MAX;

	if (type == show_ipv4_peer || type == show_ipv4_all) {
		afi = AFI_IP;
	} else if (type == show_ipv6_peer || type == show_ipv6_all) {
		afi = AFI_IP6;
	}

	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
		if (!CHECK_FLAG(peer->flags, PEER_FLAG_CONFIG_NODE))
			continue;

		switch (type) {
		case show_all:
			bgp_show_peer(vty, peer, use_json, json);
			nbr_output = true;
			break;
		case show_peer:
			if (conf_if) {
				if ((peer->conf_if
				     && !strcmp(peer->conf_if, conf_if))
				    || (peer->hostname
					&& !strcmp(peer->hostname, conf_if))) {
					find = 1;
					bgp_show_peer(vty, peer, use_json,
						      json);
				}
			} else {
				if (sockunion_same(&peer->connection->su, su)) {
					find = 1;
					bgp_show_peer(vty, peer, use_json,
						      json);
				}
			}
			break;
		case show_ipv4_peer:
		case show_ipv6_peer:
			FOREACH_SAFI (safi) {
				if (peer->afc[afi][safi]) {
					if (conf_if) {
						if ((peer->conf_if
						     && !strcmp(peer->conf_if, conf_if))
						    || (peer->hostname
							&& !strcmp(peer->hostname, conf_if))) {
							find = 1;
							bgp_show_peer(vty, peer, use_json,
								      json);
							break;
						}
					} else {
						if (sockunion_same(&peer->connection
									    ->su,
								   su)) {
							find = 1;
							bgp_show_peer(vty, peer, use_json,
								      json);
							break;
						}
					}
				}
			}
			break;
		case show_ipv4_all:
		case show_ipv6_all:
			FOREACH_SAFI (safi) {
				if (peer->afc[afi][safi]) {
					bgp_show_peer(vty, peer, use_json, json);
					nbr_output = true;
					break;
				}
			}
			break;
		}
	}

	if ((type == show_peer || type == show_ipv4_peer ||
	     type == show_ipv6_peer) && !find) {
		if (use_json)
			json_object_boolean_true_add(json, "bgpNoSuchNeighbor");
		else
			vty_out(vty, "%% No such neighbor in this view/vrf\n");
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

static void bgp_show_neighbor_graceful_restart_vty(struct vty *vty, struct bgp *bgp,
						   enum show_type type, const char *ip_str,
						   afi_t afi, json_object *json)
{
	int ret;
	union sockunion su;

	if (!json)
		bgp_show_global_graceful_restart_mode_vty(vty, bgp);

	if (ip_str) {
		ret = str2sockunion(ip_str, &su);
		if (ret < 0)
			bgp_show_neighbor_graceful_restart(vty, bgp, type, NULL,
							   ip_str, afi, json);
		else
			bgp_show_neighbor_graceful_restart(vty, bgp, type, &su,
							   NULL, afi, json);
	} else
		bgp_show_neighbor_graceful_restart(vty, bgp, type, NULL, NULL,
						   afi, json);
}

static void bgp_show_all_instances_neighbors_vty(struct vty *vty,
						 enum show_type type,
						 const char *ip_str,
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

		if (type == show_peer || type == show_ipv4_peer ||
		    type == show_ipv6_peer) {
			ret = str2sockunion(ip_str, &su);
			if (ret < 0)
				bgp_show_neighbor(vty, bgp, type, NULL, ip_str,
						  use_json, json);
			else
				bgp_show_neighbor(vty, bgp, type, &su, NULL,
						  use_json, json);
		} else {
			bgp_show_neighbor(vty, bgp, type, NULL, NULL,
					  use_json, json);
		}
		json_object_free(json);
		json = NULL;
	}

	if (use_json)
		vty_out(vty, "}\n");
	else if (!nbr_output)
		vty_out(vty, "%% BGP instance not found\n");
}

static int bgp_show_neighbor_vty(struct vty *vty, const char *name,
				 enum show_type type, const char *ip_str,
				 bool use_json)
{
	int ret;
	struct bgp *bgp;
	union sockunion su;
	json_object *json = NULL;

	if (name) {
		if (strmatch(name, "all")) {
			bgp_show_all_instances_neighbors_vty(vty, type, ip_str,
							     use_json);
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
		json = json_object_new_object();
		if (ip_str) {
			ret = str2sockunion(ip_str, &su);
			if (ret < 0)
				bgp_show_neighbor(vty, bgp, type, NULL, ip_str,
						  use_json, json);
			else
				bgp_show_neighbor(vty, bgp, type, &su, NULL,
						  use_json, json);
		} else {
			bgp_show_neighbor(vty, bgp, type, NULL, NULL, use_json,
					  json);
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

/* "show [ip] bgp neighbors graceful-restart" commands.  */
DEFPY (show_ip_bgp_neighbors_graceful_restart,
       show_ip_bgp_neighbors_graceful_restart_cmd,
       "show bgp [<ipv4|ipv6>]$afi [<view|vrf> VIEWVRFNAME$vrf] neighbors [<A.B.C.D|X:X::X:X|WORD>$neigh] graceful-restart [json]$json",
       SHOW_STR
       BGP_STR
       IP_STR
       IPV6_STR
       BGP_INSTANCE_HELP_STR
       NEIGHBOR_STR
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on BGP configured interface\n"
       GR_SHOW
       JSON_STR)
{
	enum show_type sh_type = show_all;
	afi_t afiz = AFI_IP;
	bool uj = !!json;
	struct bgp *bgp;

	if (afi)
		afiz = bgp_vty_afi_from_str(afi);

	if (neigh)
		sh_type = show_peer;

	bgp = vrf ? bgp_lookup_by_name(vrf) : bgp_get_default();

	if (!bgp) {
		vty_out(vty, "No such bgp instance %s", vrf ? vrf : "");
		return CMD_WARNING;
	}

	return bgp_show_neighbor_graceful_restart_afi_all(vty, bgp, sh_type, neigh, afiz, uj);
}

/* "show [ip] bgp neighbors" commands.  */
DEFUN (show_ip_bgp_neighbors,
       show_ip_bgp_neighbors_cmd,
       "show [ip] bgp [<view|vrf> VIEWVRFNAME] [<ipv4|ipv6>] neighbors [<A.B.C.D|X:X::X:X|WORD>] [json]",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_INSTANCE_HELP_STR
       BGP_AF_STR
       BGP_AF_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Neighbor on BGP configured interface\n"
       JSON_STR)
{
	char *vrf = NULL;
	char *sh_arg = NULL;
	enum show_type sh_type;
	afi_t afi = AFI_MAX;

	bool uj = use_json(argc, argv);

	int idx = 0;

	/* [<vrf> VIEWVRFNAME] */
	if (argv_find(argv, argc, "vrf", &idx)) {
		vrf = argv[idx + 1]->arg;
		if (vrf && strmatch(vrf, VRF_DEFAULT_NAME))
			vrf = NULL;
	} else if (argv_find(argv, argc, "view", &idx))
		/* [<view> VIEWVRFNAME] */
		vrf = argv[idx + 1]->arg;

	idx++;

	if (argv_find(argv, argc, "ipv4", &idx)) {
		sh_type = show_ipv4_all;
		afi = AFI_IP;
	} else if (argv_find(argv, argc, "ipv6", &idx)) {
		sh_type = show_ipv6_all;
		afi = AFI_IP6;
	} else {
		sh_type = show_all;
	}

	if (argv_find(argv, argc, "A.B.C.D", &idx)
	    || argv_find(argv, argc, "X:X::X:X", &idx)
	    || argv_find(argv, argc, "WORD", &idx)) {
		sh_type = show_peer;
		sh_arg = argv[idx]->arg;
	}

	if (sh_type == show_peer && afi == AFI_IP) {
		sh_type = show_ipv4_peer;
	} else if (sh_type == show_peer && afi == AFI_IP6) {
		sh_type = show_ipv6_peer;
	}

	return bgp_show_neighbor_vty(vty, vrf, sh_type, sh_arg, uj);
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
	vty_out(vty, "[%p] (%ld) %s\n", (void *)com, com->refcnt,
		community_str(com, false, false));
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
	vty_out(vty, "[%p] (%ld) %s\n", (void *)lcom, lcom->refcnt,
		lcommunity_str(lcom, false, false));
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
/* Graceful Restart */

static void bgp_show_global_graceful_restart_mode_vty(struct vty *vty,
						      struct bgp *bgp)
{


	vty_out(vty, "\n%s", SHOW_GR_HEADER);

	enum global_mode bgp_global_gr_mode = bgp_global_gr_mode_get(bgp);

	switch (bgp_global_gr_mode) {

	case GLOBAL_HELPER:
		vty_out(vty, "Global BGP GR Mode :  Helper\n");
		break;

	case GLOBAL_GR:
		vty_out(vty, "Global BGP GR Mode :  Restart\n");
		break;

	case GLOBAL_DISABLE:
		vty_out(vty, "Global BGP GR Mode :  Disable\n");
		break;

	case GLOBAL_INVALID:
		vty_out(vty,
			"Global BGP GR Mode  Invalid\n");
		break;
	}
	vty_out(vty, "\n");
}

static int bgp_show_neighbor_graceful_restart_afi_all(struct vty *vty, struct bgp *bgp,
						      enum show_type type, const char *ip_str,
						      afi_t afi, bool use_json)
{
	json_object *json = NULL;

	if (use_json)
		json = json_object_new_object();

	if ((afi == AFI_MAX) && (ip_str == NULL)) {
		afi = AFI_IP;

		while ((afi != AFI_L2VPN) && (afi < AFI_MAX)) {
			bgp_show_neighbor_graceful_restart_vty(vty, bgp, type, ip_str, afi, json);
			afi++;
		}
	} else if (afi != AFI_MAX) {
		bgp_show_neighbor_graceful_restart_vty(vty, bgp, type, ip_str, afi, json);
	} else {
		if (json)
			json_object_free(json);
		return CMD_ERR_INCOMPLETE;
	}

	if (json)
		vty_json(vty, json);

	return CMD_SUCCESS;
}
/* Graceful Restart */

DEFUN (show_ip_bgp_attr_info,
       show_ip_bgp_attr_info_cmd,
       "show [ip] bgp attribute-info",
       SHOW_STR
       IP_STR
       BGP_STR
       "List all bgp attribute information\n")
{
	attr_show_all(vty);
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
			json_object_string_addf(
				json, "routeDistinguisher", "%s",
				bgp->vpn_policy[afi].tovpn_rd_pretty);
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

DEFUN (show_bgp_l2vpn_evpn_updgrps,
	show_bgp_l2vpn_evpn_updgrps_cmd,
	"show [ip] bgp l2vpn evpn update-groups",
	SHOW_STR
	IP_STR
	BGP_STR
	"l2vpn address family\n"
	"evpn sub-address family\n"
	"Detailed info about dynamic update groups\n")
{
	char *vrf = NULL;
	uint64_t subgrp_id = 0;

	bgp_show_update_groups(vty, vrf, AFI_L2VPN, SAFI_EVPN, subgrp_id, 0);
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
	bool af_cfgd;
	json_object *json_peer_group = NULL;
	json_object *json_peer_group_afc = NULL;
	json_object *json_peer_group_members = NULL;
	json_object *json_peer_group_dynamic = NULL;
	json_object *json_peer_group_dynamic_af = NULL;
	json_object *json_peer_group_ranges = NULL;

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
			asn_asn2json(json, "remoteAs", group->bgp->as,
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
		}
		if (json)
			json_object_object_add(json_peer_group, "members",
					       json_peer_group_members);
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

DEFUN (bgp_redistribute_ipv4,
       bgp_redistribute_ipv4_cmd,
       "redistribute " FRR_IP_REDIST_STR_BGPD,
       "Redistribute information from another routing protocol\n"
       FRR_IP_REDIST_HELP_STR_BGPD)
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_protocol = 1;
	int type;

	type = proto_redistnum(AFI_IP, argv[idx_protocol]->text);
	if (type < 0) {
		vty_out(vty, "%% Invalid route type\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	bgp_redist_add(bgp, AFI_IP, type, 0);
	return bgp_redistribute_set(bgp, AFI_IP, type, 0, false);
}

ALIAS_HIDDEN(
	bgp_redistribute_ipv4, bgp_redistribute_ipv4_hidden_cmd,
	"redistribute " FRR_IP_REDIST_STR_BGPD,
	"Redistribute information from another routing protocol\n" FRR_IP_REDIST_HELP_STR_BGPD)

DEFUN (bgp_redistribute_ipv4_rmap,
       bgp_redistribute_ipv4_rmap_cmd,
       "redistribute " FRR_IP_REDIST_STR_BGPD " route-map RMAP_NAME",
       "Redistribute information from another routing protocol\n"
       FRR_IP_REDIST_HELP_STR_BGPD
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_protocol = 1;
	int idx_word = 3;
	int type;
	struct bgp_redist *red;
	bool changed;
	struct route_map *route_map = route_map_lookup_warn_noexist(
		vty, argv[idx_word]->arg);

	type = proto_redistnum(AFI_IP, argv[idx_protocol]->text);
	if (type < 0) {
		vty_out(vty, "%% Invalid route type\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	red = bgp_redist_add(bgp, AFI_IP, type, 0);
	changed =
		bgp_redistribute_rmap_set(red, argv[idx_word]->arg, route_map);
	return bgp_redistribute_set(bgp, AFI_IP, type, 0, changed);
}

ALIAS_HIDDEN(
	bgp_redistribute_ipv4_rmap, bgp_redistribute_ipv4_rmap_hidden_cmd,
	"redistribute " FRR_IP_REDIST_STR_BGPD " route-map RMAP_NAME",
	"Redistribute information from another routing protocol\n" FRR_IP_REDIST_HELP_STR_BGPD
	"Route map reference\n"
	"Pointer to route-map entries\n")

DEFUN (bgp_redistribute_ipv4_metric,
       bgp_redistribute_ipv4_metric_cmd,
       "redistribute " FRR_IP_REDIST_STR_BGPD " metric (0-4294967295)",
       "Redistribute information from another routing protocol\n"
       FRR_IP_REDIST_HELP_STR_BGPD
       "Metric for redistributed routes\n"
       "Default metric\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_protocol = 1;
	int idx_number = 3;
	int type;
	uint32_t metric;
	struct bgp_redist *red;
	bool changed;

	type = proto_redistnum(AFI_IP, argv[idx_protocol]->text);
	if (type < 0) {
		vty_out(vty, "%% Invalid route type\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	metric = strtoul(argv[idx_number]->arg, NULL, 10);

	red = bgp_redist_add(bgp, AFI_IP, type, 0);
	changed = bgp_redistribute_metric_set(bgp, red, AFI_IP, type, metric);
	return bgp_redistribute_set(bgp, AFI_IP, type, 0, changed);
}

ALIAS_HIDDEN(
	bgp_redistribute_ipv4_metric, bgp_redistribute_ipv4_metric_hidden_cmd,
	"redistribute " FRR_IP_REDIST_STR_BGPD " metric (0-4294967295)",
	"Redistribute information from another routing protocol\n" FRR_IP_REDIST_HELP_STR_BGPD
	"Metric for redistributed routes\n"
	"Default metric\n")

DEFUN (bgp_redistribute_ipv4_rmap_metric,
       bgp_redistribute_ipv4_rmap_metric_cmd,
       "redistribute " FRR_IP_REDIST_STR_BGPD " route-map RMAP_NAME metric (0-4294967295)",
       "Redistribute information from another routing protocol\n"
       FRR_IP_REDIST_HELP_STR_BGPD
       "Route map reference\n"
       "Pointer to route-map entries\n"
       "Metric for redistributed routes\n"
       "Default metric\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_protocol = 1;
	int idx_word = 3;
	int idx_number = 5;
	int type;
	uint32_t metric;
	struct bgp_redist *red;
	bool changed;
	struct route_map *route_map =
		route_map_lookup_warn_noexist(vty, argv[idx_word]->arg);

	type = proto_redistnum(AFI_IP, argv[idx_protocol]->text);
	if (type < 0) {
		vty_out(vty, "%% Invalid route type\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	metric = strtoul(argv[idx_number]->arg, NULL, 10);

	red = bgp_redist_add(bgp, AFI_IP, type, 0);
	changed =
		bgp_redistribute_rmap_set(red, argv[idx_word]->arg, route_map);
	changed |= bgp_redistribute_metric_set(bgp, red, AFI_IP, type, metric);
	return bgp_redistribute_set(bgp, AFI_IP, type, 0, changed);
}

ALIAS_HIDDEN(
	bgp_redistribute_ipv4_rmap_metric,
	bgp_redistribute_ipv4_rmap_metric_hidden_cmd,
	"redistribute " FRR_IP_REDIST_STR_BGPD
	" route-map RMAP_NAME metric (0-4294967295)",
	"Redistribute information from another routing protocol\n" FRR_IP_REDIST_HELP_STR_BGPD
	"Route map reference\n"
	"Pointer to route-map entries\n"
	"Metric for redistributed routes\n"
	"Default metric\n")

DEFUN (bgp_redistribute_ipv4_metric_rmap,
       bgp_redistribute_ipv4_metric_rmap_cmd,
       "redistribute " FRR_IP_REDIST_STR_BGPD " metric (0-4294967295) route-map RMAP_NAME",
       "Redistribute information from another routing protocol\n"
       FRR_IP_REDIST_HELP_STR_BGPD
       "Metric for redistributed routes\n"
       "Default metric\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_protocol = 1;
	int idx_number = 3;
	int idx_word = 5;
	int type;
	uint32_t metric;
	struct bgp_redist *red;
	bool changed;
	struct route_map *route_map =
		route_map_lookup_warn_noexist(vty, argv[idx_word]->arg);

	type = proto_redistnum(AFI_IP, argv[idx_protocol]->text);
	if (type < 0) {
		vty_out(vty, "%% Invalid route type\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	metric = strtoul(argv[idx_number]->arg, NULL, 10);

	red = bgp_redist_add(bgp, AFI_IP, type, 0);
	changed = bgp_redistribute_metric_set(bgp, red, AFI_IP, type, metric);
	changed |=
		bgp_redistribute_rmap_set(red, argv[idx_word]->arg, route_map);
	return bgp_redistribute_set(bgp, AFI_IP, type, 0, changed);
}

ALIAS_HIDDEN(
	bgp_redistribute_ipv4_metric_rmap,
	bgp_redistribute_ipv4_metric_rmap_hidden_cmd,
	"redistribute " FRR_IP_REDIST_STR_BGPD
	" metric (0-4294967295) route-map RMAP_NAME",
	"Redistribute information from another routing protocol\n" FRR_IP_REDIST_HELP_STR_BGPD
	"Metric for redistributed routes\n"
	"Default metric\n"
	"Route map reference\n"
	"Pointer to route-map entries\n")

DEFUN (bgp_redistribute_ipv4_ospf,
       bgp_redistribute_ipv4_ospf_cmd,
       "redistribute <ospf|table|table-direct> (1-65535)",
       "Redistribute information from another routing protocol\n"
       "Open Shortest Path First (OSPFv2)\n"
       "Non-main Kernel Routing Table\n"
       "Non-main Kernel Routing Table - Direct\n"
       "Instance ID/Table ID\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_ospf_table = 1;
	int idx_number = 2;
	unsigned short instance;
	unsigned short protocol;

	instance = strtoul(argv[idx_number]->arg, NULL, 10);

	if (strncmp(argv[idx_ospf_table]->arg, "o", 1) == 0)
		protocol = ZEBRA_ROUTE_OSPF;
	else {
		if (bgp->vrf_id != VRF_DEFAULT) {
			vty_out(vty,
				"%% Only default BGP instance can use '%s'\n",
				argv[idx_ospf_table]->arg);
			return CMD_WARNING_CONFIG_FAILED;
		}
		if (strncmp(argv[idx_ospf_table]->arg, "table-direct",
			    strlen("table-direct")) == 0) {
			protocol = ZEBRA_ROUTE_TABLE_DIRECT;
			if (instance == RT_TABLE_MAIN ||
			    instance == RT_TABLE_LOCAL) {
				vty_out(vty,
					"%% 'table-direct', can not use %u routing table\n",
					instance);
				return CMD_WARNING_CONFIG_FAILED;
			}
		} else
			protocol = ZEBRA_ROUTE_TABLE;
	}

	bgp_redist_add(bgp, AFI_IP, protocol, instance);
	return bgp_redistribute_set(bgp, AFI_IP, protocol, instance, false);
}

ALIAS_HIDDEN(bgp_redistribute_ipv4_ospf, bgp_redistribute_ipv4_ospf_hidden_cmd,
	     "redistribute <ospf|table|table-direct> (1-65535)",
	     "Redistribute information from another routing protocol\n"
	     "Open Shortest Path First (OSPFv2)\n"
	     "Non-main Kernel Routing Table\n"
	     "Non-main Kernel Routing Table - Direct\n"
	     "Instance ID/Table ID\n")

DEFUN (bgp_redistribute_ipv4_ospf_rmap,
       bgp_redistribute_ipv4_ospf_rmap_cmd,
       "redistribute <ospf|table|table-direct> (1-65535) route-map RMAP_NAME",
       "Redistribute information from another routing protocol\n"
       "Open Shortest Path First (OSPFv2)\n"
       "Non-main Kernel Routing Table\n"
       "Non-main Kernel Routing Table - Direct\n"
       "Instance ID/Table ID\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_ospf_table = 1;
	int idx_number = 2;
	int idx_word = 4;
	struct bgp_redist *red;
	unsigned short instance;
	int protocol;
	bool changed;
	struct route_map *route_map =
		route_map_lookup_warn_noexist(vty, argv[idx_word]->arg);

	instance = strtoul(argv[idx_number]->arg, NULL, 10);

	if (strncmp(argv[idx_ospf_table]->arg, "o", 1) == 0)
		protocol = ZEBRA_ROUTE_OSPF;
	else {
		if (bgp->vrf_id != VRF_DEFAULT) {
			vty_out(vty,
				"%% Only default BGP instance can use '%s'\n",
				argv[idx_ospf_table]->arg);
			return CMD_WARNING_CONFIG_FAILED;
		}
		if (strncmp(argv[idx_ospf_table]->arg, "table-direct",
			    strlen("table-direct")) == 0) {
			protocol = ZEBRA_ROUTE_TABLE_DIRECT;
			if (instance == RT_TABLE_MAIN ||
			    instance == RT_TABLE_LOCAL) {
				vty_out(vty,
					"%% 'table-direct', can not use %u routing table\n",
					instance);
				return CMD_WARNING_CONFIG_FAILED;
			}
		} else
			protocol = ZEBRA_ROUTE_TABLE;
	}

	red = bgp_redist_add(bgp, AFI_IP, protocol, instance);
	changed =
		bgp_redistribute_rmap_set(red, argv[idx_word]->arg, route_map);
	return bgp_redistribute_set(bgp, AFI_IP, protocol, instance, changed);
}

ALIAS_HIDDEN(bgp_redistribute_ipv4_ospf_rmap,
	     bgp_redistribute_ipv4_ospf_rmap_hidden_cmd,
	     "redistribute <ospf|table|table-direct> (1-65535) route-map RMAP_NAME",
	     "Redistribute information from another routing protocol\n"
	     "Open Shortest Path First (OSPFv2)\n"
	     "Non-main Kernel Routing Table\n"
	     "Non-main Kernel Routing Table - Direct\n"
	     "Instance ID/Table ID\n"
	     "Route map reference\n"
	     "Pointer to route-map entries\n")

DEFUN (bgp_redistribute_ipv4_ospf_metric,
       bgp_redistribute_ipv4_ospf_metric_cmd,
       "redistribute <ospf|table|table-direct> (1-65535) metric (0-4294967295)",
       "Redistribute information from another routing protocol\n"
       "Open Shortest Path First (OSPFv2)\n"
       "Non-main Kernel Routing Table\n"
       "Non-main Kernel Routing Table - Direct\n"
       "Instance ID/Table ID\n"
       "Metric for redistributed routes\n"
       "Default metric\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_ospf_table = 1;
	int idx_number = 2;
	int idx_number_2 = 4;
	uint32_t metric;
	struct bgp_redist *red;
	unsigned short instance;
	int protocol;
	bool changed;

	instance = strtoul(argv[idx_number]->arg, NULL, 10);

	if (strncmp(argv[idx_ospf_table]->arg, "o", 1) == 0)
		protocol = ZEBRA_ROUTE_OSPF;
	else {
		if (bgp->vrf_id != VRF_DEFAULT) {
			vty_out(vty,
				"%% Only default BGP instance can use '%s'\n",
				argv[idx_ospf_table]->arg);
			return CMD_WARNING_CONFIG_FAILED;
		}
		if (strncmp(argv[idx_ospf_table]->arg, "table-direct",
			    strlen("table-direct")) == 0) {
			protocol = ZEBRA_ROUTE_TABLE_DIRECT;
			if (instance == RT_TABLE_MAIN ||
			    instance == RT_TABLE_LOCAL) {
				vty_out(vty,
					"%% 'table-direct', can not use %u routing table\n",
					instance);
				return CMD_WARNING_CONFIG_FAILED;
			}
		} else
			protocol = ZEBRA_ROUTE_TABLE;
	}

	metric = strtoul(argv[idx_number_2]->arg, NULL, 10);

	red = bgp_redist_add(bgp, AFI_IP, protocol, instance);
	changed = bgp_redistribute_metric_set(bgp, red, AFI_IP, protocol,
						metric);
	return bgp_redistribute_set(bgp, AFI_IP, protocol, instance, changed);
}

ALIAS_HIDDEN(bgp_redistribute_ipv4_ospf_metric,
	     bgp_redistribute_ipv4_ospf_metric_hidden_cmd,
	     "redistribute <ospf|table|table-direct> (1-65535) metric (0-4294967295)",
	     "Redistribute information from another routing protocol\n"
	     "Open Shortest Path First (OSPFv2)\n"
	     "Non-main Kernel Routing Table\n"
	     "Non-main Kernel Routing Table - Direct\n"
	     "Instance ID/Table ID\n"
	     "Metric for redistributed routes\n"
	     "Default metric\n")

DEFUN (bgp_redistribute_ipv4_ospf_rmap_metric,
       bgp_redistribute_ipv4_ospf_rmap_metric_cmd,
       "redistribute <ospf|table|table-direct> (1-65535) route-map RMAP_NAME metric (0-4294967295)",
       "Redistribute information from another routing protocol\n"
       "Open Shortest Path First (OSPFv2)\n"
       "Non-main Kernel Routing Table\n"
       "Non-main Kernel Routing Table - Direct\n"
       "Instance ID/Table ID\n"
       "Route map reference\n"
       "Pointer to route-map entries\n"
       "Metric for redistributed routes\n"
       "Default metric\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_ospf_table = 1;
	int idx_number = 2;
	int idx_word = 4;
	int idx_number_2 = 6;
	uint32_t metric;
	struct bgp_redist *red;
	unsigned short instance;
	int protocol;
	bool changed;
	struct route_map *route_map =
		route_map_lookup_warn_noexist(vty, argv[idx_word]->arg);

	instance = strtoul(argv[idx_number]->arg, NULL, 10);

	if (strncmp(argv[idx_ospf_table]->arg, "o", 1) == 0)
		protocol = ZEBRA_ROUTE_OSPF;
	else {
		if (bgp->vrf_id != VRF_DEFAULT) {
			vty_out(vty,
				"%% Only default BGP instance can use '%s'\n",
				argv[idx_ospf_table]->arg);
			return CMD_WARNING_CONFIG_FAILED;
		}
		if (strncmp(argv[idx_ospf_table]->arg, "table-direct",
			    strlen("table-direct")) == 0) {
			protocol = ZEBRA_ROUTE_TABLE_DIRECT;
			if (instance == RT_TABLE_MAIN ||
			    instance == RT_TABLE_LOCAL) {
				vty_out(vty,
					"%% 'table-direct', can not use %u routing table\n",
					instance);
				return CMD_WARNING_CONFIG_FAILED;
			}
		} else
			protocol = ZEBRA_ROUTE_TABLE;
	}

	metric = strtoul(argv[idx_number_2]->arg, NULL, 10);

	red = bgp_redist_add(bgp, AFI_IP, protocol, instance);
	changed =
		bgp_redistribute_rmap_set(red, argv[idx_word]->arg, route_map);
	changed |= bgp_redistribute_metric_set(bgp, red, AFI_IP, protocol,
						metric);
	return bgp_redistribute_set(bgp, AFI_IP, protocol, instance, changed);
}

ALIAS_HIDDEN(
	bgp_redistribute_ipv4_ospf_rmap_metric,
	bgp_redistribute_ipv4_ospf_rmap_metric_hidden_cmd,
	"redistribute <ospf|table|table-direct> (1-65535) route-map RMAP_NAME metric (0-4294967295)",
	"Redistribute information from another routing protocol\n"
	"Open Shortest Path First (OSPFv2)\n"
	"Non-main Kernel Routing Table\n"
        "Non-main Kernel Routing Table - Direct\n"
	"Instance ID/Table ID\n"
	"Route map reference\n"
	"Pointer to route-map entries\n"
	"Metric for redistributed routes\n"
	"Default metric\n")

DEFUN (bgp_redistribute_ipv4_ospf_metric_rmap,
       bgp_redistribute_ipv4_ospf_metric_rmap_cmd,
       "redistribute <ospf|table|table-direct> (1-65535) metric (0-4294967295) route-map RMAP_NAME",
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
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_ospf_table = 1;
	int idx_number = 2;
	int idx_number_2 = 4;
	int idx_word = 6;
	uint32_t metric;
	struct bgp_redist *red;
	unsigned short instance;
	int protocol;
	bool changed;
	struct route_map *route_map =
		route_map_lookup_warn_noexist(vty, argv[idx_word]->arg);

	instance = strtoul(argv[idx_number]->arg, NULL, 10);

	if (strncmp(argv[idx_ospf_table]->arg, "o", 1) == 0)
		protocol = ZEBRA_ROUTE_OSPF;
	else {
		if (bgp->vrf_id != VRF_DEFAULT) {
			vty_out(vty,
				"%% Only default BGP instance can use '%s'\n",
				argv[idx_ospf_table]->arg);
			return CMD_WARNING_CONFIG_FAILED;
		} else if (strncmp(argv[idx_ospf_table]->arg, "table-direct",
				   strlen("table-direct")) == 0) {
			protocol = ZEBRA_ROUTE_TABLE_DIRECT;
			if (instance == RT_TABLE_MAIN ||
			    instance == RT_TABLE_LOCAL) {
				vty_out(vty,
					"%% 'table-direct', can not use %u routing table\n",
					instance);
				return CMD_WARNING_CONFIG_FAILED;
			}
		} else
			protocol = ZEBRA_ROUTE_TABLE;
	}

	instance = strtoul(argv[idx_number]->arg, NULL, 10);
	metric = strtoul(argv[idx_number_2]->arg, NULL, 10);

	red = bgp_redist_add(bgp, AFI_IP, protocol, instance);
	changed = bgp_redistribute_metric_set(bgp, red, AFI_IP, protocol,
						metric);
	changed |=
		bgp_redistribute_rmap_set(red, argv[idx_word]->arg, route_map);
	return bgp_redistribute_set(bgp, AFI_IP, protocol, instance, changed);
}

ALIAS_HIDDEN(
	bgp_redistribute_ipv4_ospf_metric_rmap,
	bgp_redistribute_ipv4_ospf_metric_rmap_hidden_cmd,
	"redistribute <ospf|table|table-direct> (1-65535) metric (0-4294967295) route-map RMAP_NAME",
	"Redistribute information from another routing protocol\n"
	"Open Shortest Path First (OSPFv2)\n"
	"Non-main Kernel Routing Table\n"
        "Non-main Kernel Routing Table - Direct\n"
	"Instance ID/Table ID\n"
	"Metric for redistributed routes\n"
	"Default metric\n"
	"Route map reference\n"
	"Pointer to route-map entries\n")

DEFUN (no_bgp_redistribute_ipv4_ospf,
       no_bgp_redistribute_ipv4_ospf_cmd,
       "no redistribute <ospf|table|table-direct> (1-65535) [{metric (0-4294967295)|route-map RMAP_NAME}]",
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
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_ospf_table = 2;
	int idx_number = 3;
	unsigned short instance;
	int protocol;

	instance = strtoul(argv[idx_number]->arg, NULL, 10);

	if (strncmp(argv[idx_ospf_table]->arg, "o", 1) == 0)
		protocol = ZEBRA_ROUTE_OSPF;
	else {
		if (bgp->vrf_id != VRF_DEFAULT) {
			vty_out(vty,
				"%% Only default BGP instance can use '%s'\n",
				argv[idx_ospf_table]->arg);
			return CMD_WARNING_CONFIG_FAILED;
		}
		if (strncmp(argv[idx_ospf_table]->arg, "table-direct",
			    strlen("table-direct")) == 0) {
			protocol = ZEBRA_ROUTE_TABLE_DIRECT;
			if (instance == RT_TABLE_MAIN ||
			    instance == RT_TABLE_LOCAL) {
				vty_out(vty,
					"%% 'table-direct', can not use %u routing table\n",
					instance);
				return CMD_WARNING_CONFIG_FAILED;
			}
		} else
			protocol = ZEBRA_ROUTE_TABLE;
	}

	bgp_redistribute_unset(bgp, AFI_IP, protocol, instance);
	return CMD_SUCCESS;
}

ALIAS_HIDDEN(
	no_bgp_redistribute_ipv4_ospf, no_bgp_redistribute_ipv4_ospf_hidden_cmd,
	"no redistribute <ospf|table|table-direct> (1-65535) [{metric (0-4294967295)|route-map RMAP_NAME}]",
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

DEFUN (no_bgp_redistribute_ipv4,
       no_bgp_redistribute_ipv4_cmd,
       "no redistribute " FRR_IP_REDIST_STR_BGPD " [{metric (0-4294967295)|route-map RMAP_NAME}]",
       NO_STR
       "Redistribute information from another routing protocol\n"
       FRR_IP_REDIST_HELP_STR_BGPD
       "Metric for redistributed routes\n"
       "Default metric\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_protocol = 2;
	int type;

	type = proto_redistnum(AFI_IP, argv[idx_protocol]->text);
	if (type < 0) {
		vty_out(vty, "%% Invalid route type\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	bgp_redistribute_unset(bgp, AFI_IP, type, 0);
	return CMD_SUCCESS;
}

ALIAS_HIDDEN(
	no_bgp_redistribute_ipv4, no_bgp_redistribute_ipv4_hidden_cmd,
	"no redistribute " FRR_IP_REDIST_STR_BGPD
	" [{metric (0-4294967295)|route-map RMAP_NAME}]",
	NO_STR
	"Redistribute information from another routing protocol\n" FRR_IP_REDIST_HELP_STR_BGPD
	"Metric for redistributed routes\n"
	"Default metric\n"
	"Route map reference\n"
	"Pointer to route-map entries\n")

DEFUN (bgp_redistribute_ipv6,
       bgp_redistribute_ipv6_cmd,
       "redistribute " FRR_IP6_REDIST_STR_BGPD,
       "Redistribute information from another routing protocol\n"
       FRR_IP6_REDIST_HELP_STR_BGPD)
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_protocol = 1;
	int type;

	type = proto_redistnum(AFI_IP6, argv[idx_protocol]->text);
	if (type < 0) {
		vty_out(vty, "%% Invalid route type\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	bgp_redist_add(bgp, AFI_IP6, type, 0);
	return bgp_redistribute_set(bgp, AFI_IP6, type, 0, false);
}

DEFUN (bgp_redistribute_ipv6_rmap,
       bgp_redistribute_ipv6_rmap_cmd,
       "redistribute " FRR_IP6_REDIST_STR_BGPD " route-map RMAP_NAME",
       "Redistribute information from another routing protocol\n"
       FRR_IP6_REDIST_HELP_STR_BGPD
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_protocol = 1;
	int idx_word = 3;
	int type;
	struct bgp_redist *red;
	bool changed;
	struct route_map *route_map =
		route_map_lookup_warn_noexist(vty, argv[idx_word]->arg);

	type = proto_redistnum(AFI_IP6, argv[idx_protocol]->text);
	if (type < 0) {
		vty_out(vty, "%% Invalid route type\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	red = bgp_redist_add(bgp, AFI_IP6, type, 0);
	changed =
		bgp_redistribute_rmap_set(red, argv[idx_word]->arg, route_map);
	return bgp_redistribute_set(bgp, AFI_IP6, type, 0, changed);
}

DEFUN (bgp_redistribute_ipv6_metric,
       bgp_redistribute_ipv6_metric_cmd,
       "redistribute " FRR_IP6_REDIST_STR_BGPD " metric (0-4294967295)",
       "Redistribute information from another routing protocol\n"
       FRR_IP6_REDIST_HELP_STR_BGPD
       "Metric for redistributed routes\n"
       "Default metric\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_protocol = 1;
	int idx_number = 3;
	int type;
	uint32_t metric;
	struct bgp_redist *red;
	bool changed;

	type = proto_redistnum(AFI_IP6, argv[idx_protocol]->text);
	if (type < 0) {
		vty_out(vty, "%% Invalid route type\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	metric = strtoul(argv[idx_number]->arg, NULL, 10);

	red = bgp_redist_add(bgp, AFI_IP6, type, 0);
	changed = bgp_redistribute_metric_set(bgp, red, AFI_IP6, type, metric);
	return bgp_redistribute_set(bgp, AFI_IP6, type, 0, changed);
}

DEFUN (bgp_redistribute_ipv6_rmap_metric,
       bgp_redistribute_ipv6_rmap_metric_cmd,
       "redistribute " FRR_IP6_REDIST_STR_BGPD " route-map RMAP_NAME metric (0-4294967295)",
       "Redistribute information from another routing protocol\n"
       FRR_IP6_REDIST_HELP_STR_BGPD
       "Route map reference\n"
       "Pointer to route-map entries\n"
       "Metric for redistributed routes\n"
       "Default metric\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_protocol = 1;
	int idx_word = 3;
	int idx_number = 5;
	int type;
	uint32_t metric;
	struct bgp_redist *red;
	bool changed;
	struct route_map *route_map =
		route_map_lookup_warn_noexist(vty, argv[idx_word]->arg);

	type = proto_redistnum(AFI_IP6, argv[idx_protocol]->text);
	if (type < 0) {
		vty_out(vty, "%% Invalid route type\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	metric = strtoul(argv[idx_number]->arg, NULL, 10);

	red = bgp_redist_add(bgp, AFI_IP6, type, 0);
	changed =
		bgp_redistribute_rmap_set(red, argv[idx_word]->arg, route_map);
	changed |= bgp_redistribute_metric_set(bgp, red, AFI_IP6, type,
						metric);
	return bgp_redistribute_set(bgp, AFI_IP6, type, 0, changed);
}

DEFPY(bgp_redistribute_ipv6_table, bgp_redistribute_ipv6_table_cmd,
      "redistribute table-direct (1-65535)$table_id [{metric$metric (0-4294967295)$metric_val|route-map WORD$rmap}]",
      "Redistribute information from another routing protocol\n"
      "Non-main Kernel Routing Table - Direct\n"
      "Table ID\n"
      "Metric for redistributed routes\n"
      "Default metric\n"
      "Route map reference\n"
      "Pointer to route-map entries\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	bool changed = false;
	struct route_map *route_map = NULL;
	struct bgp_redist *red;

	if (rmap)
		route_map = route_map_lookup_warn_noexist(vty, rmap);

	if (bgp->vrf_id != VRF_DEFAULT) {
		vty_out(vty,
			"%% Only default BGP instance can use 'table-direct'\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	if (table_id == RT_TABLE_MAIN || table_id == RT_TABLE_LOCAL) {
		vty_out(vty,
			"%% 'table-direct', can not use %lu routing table\n",
			table_id);
		return CMD_WARNING_CONFIG_FAILED;
	}

	red = bgp_redist_add(bgp, AFI_IP6, ZEBRA_ROUTE_TABLE_DIRECT, table_id);
	if (rmap)
		changed = bgp_redistribute_rmap_set(red, rmap, route_map);
	if (metric)
		changed |= bgp_redistribute_metric_set(bgp, red, AFI_IP6,
						       ZEBRA_ROUTE_TABLE_DIRECT,
						       metric_val);
	return bgp_redistribute_set(bgp, AFI_IP6, ZEBRA_ROUTE_TABLE_DIRECT,
				    table_id, changed);
}

DEFPY(no_bgp_redistribute_ipv6_table, no_bgp_redistribute_ipv6_table_cmd,
      "no redistribute table-direct (1-65535)$table_id [{metric (0-4294967295)|route-map WORD}]",
      NO_STR
      "Redistribute information from another routing protocol\n"
      "Non-main Kernel Routing Table - Direct\n"
      "Table ID\n"
      "Metric for redistributed routes\n"
      "Default metric\n"
      "Route map reference\n"
      "Pointer to route-map entries\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	if (bgp->vrf_id != VRF_DEFAULT) {
		vty_out(vty,
			"%% Only default BGP instance can use 'table-direct'\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	if (table_id == RT_TABLE_MAIN || table_id == RT_TABLE_LOCAL) {
		vty_out(vty,
			"%% 'table-direct', can not use %lu routing table\n",
			table_id);
		return CMD_WARNING_CONFIG_FAILED;
	}

	bgp_redistribute_unset(bgp, AFI_IP6, ZEBRA_ROUTE_TABLE_DIRECT, table_id);
	return CMD_SUCCESS;
}

DEFUN (bgp_redistribute_ipv6_metric_rmap,
       bgp_redistribute_ipv6_metric_rmap_cmd,
       "redistribute " FRR_IP6_REDIST_STR_BGPD " metric (0-4294967295) route-map RMAP_NAME",
       "Redistribute information from another routing protocol\n"
       FRR_IP6_REDIST_HELP_STR_BGPD
       "Metric for redistributed routes\n"
       "Default metric\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_protocol = 1;
	int idx_number = 3;
	int idx_word = 5;
	int type;
	uint32_t metric;
	struct bgp_redist *red;
	bool changed;
	struct route_map *route_map =
		route_map_lookup_warn_noexist(vty, argv[idx_word]->arg);

	type = proto_redistnum(AFI_IP6, argv[idx_protocol]->text);
	if (type < 0) {
		vty_out(vty, "%% Invalid route type\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	metric = strtoul(argv[idx_number]->arg, NULL, 10);

	red = bgp_redist_add(bgp, AFI_IP6, type, 0);
	changed = bgp_redistribute_metric_set(bgp, red, AFI_IP6, SAFI_UNICAST,
						metric);
	changed |=
		bgp_redistribute_rmap_set(red, argv[idx_word]->arg, route_map);
	return bgp_redistribute_set(bgp, AFI_IP6, type, 0, changed);
}

DEFUN (no_bgp_redistribute_ipv6,
       no_bgp_redistribute_ipv6_cmd,
       "no redistribute " FRR_IP6_REDIST_STR_BGPD " [{metric (0-4294967295)|route-map RMAP_NAME}]",
       NO_STR
       "Redistribute information from another routing protocol\n"
       FRR_IP6_REDIST_HELP_STR_BGPD
       "Metric for redistributed routes\n"
       "Default metric\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	int idx_protocol = 2;
	int type;

	type = proto_redistnum(AFI_IP6, argv[idx_protocol]->text);
	if (type < 0) {
		vty_out(vty, "%% Invalid route type\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	bgp_redistribute_unset(bgp, AFI_IP6, type, 0);
	return CMD_SUCCESS;
}

/* Neighbor update tcp-mss. */
static int peer_tcp_mss_vty(struct vty *vty, const char *peer_str,
			    const char *tcp_mss_str)
{
	struct peer *peer;
	uint32_t tcp_mss_val = 0;

	peer = peer_and_group_lookup_vty(vty, peer_str);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	if (tcp_mss_str) {
		tcp_mss_val = strtoul(tcp_mss_str, NULL, 10);
		peer_tcp_mss_set(peer, tcp_mss_val);
	} else {
		peer_tcp_mss_unset(peer);
	}

	return CMD_SUCCESS;
}

DEFUN(neighbor_tcp_mss, neighbor_tcp_mss_cmd,
      "neighbor <A.B.C.D|X:X::X:X|WORD> tcp-mss (1-65535)",
      NEIGHBOR_STR NEIGHBOR_ADDR_STR2
      "TCP max segment size\n"
      "TCP MSS value\n")
{
	int peer_index = 1;
	int mss_index = 3;

	vty_out(vty,
		" Warning: Reset BGP session for tcp-mss value to take effect\n");
	return peer_tcp_mss_vty(vty, argv[peer_index]->arg,
				argv[mss_index]->arg);
}

DEFUN(no_neighbor_tcp_mss, no_neighbor_tcp_mss_cmd,
      "no neighbor <A.B.C.D|X:X::X:X|WORD> tcp-mss [(1-65535)]",
      NO_STR NEIGHBOR_STR NEIGHBOR_ADDR_STR2
      "TCP max segment size\n"
      "TCP MSS value\n")
{
	int peer_index = 2;

	vty_out(vty,
		" Warning: Reset BGP session for tcp-mss value to take effect\n");
	return peer_tcp_mss_vty(vty, argv[peer_index]->arg, NULL);
}

DEFPY(bgp_retain_route_target, bgp_retain_route_target_cmd,
      "[no$no] bgp retain route-target all",
      NO_STR BGP_STR
      "Retain BGP updates\n"
      "Retain BGP updates based on route-target values\n"
      "Retain all BGP updates\n")
{
	bool check;
	struct bgp *bgp = VTY_GET_CONTEXT(bgp);

	check = CHECK_FLAG(bgp->af_flags[bgp_node_afi(vty)][bgp_node_safi(vty)],
			   BGP_VPNVX_RETAIN_ROUTE_TARGET_ALL);
	if (check != !no) {
		if (!no)
			SET_FLAG(bgp->af_flags[bgp_node_afi(vty)]
					      [bgp_node_safi(vty)],
				 BGP_VPNVX_RETAIN_ROUTE_TARGET_ALL);
		else
			UNSET_FLAG(bgp->af_flags[bgp_node_afi(vty)]
						[bgp_node_safi(vty)],
				   BGP_VPNVX_RETAIN_ROUTE_TARGET_ALL);
		/* trigger a flush to re-sync with ADJ-RIB-in */
		bgp_clear(vty, bgp, bgp_node_afi(vty), bgp_node_safi(vty),
			  clear_all, BGP_CLEAR_SOFT_IN, NULL);
	}
	return CMD_SUCCESS;
}

static void bgp_config_write_redistribute(struct vty *vty, struct bgp *bgp,
					  afi_t afi, safi_t safi)
{
	int i;

	/* Unicast redistribution only.  */
	if (safi != SAFI_UNICAST)
		return;

	for (i = 0; i < ZEBRA_ROUTE_MAX; i++) {
		/* Redistribute BGP does not make sense.  */
		if (i != ZEBRA_ROUTE_BGP) {
			struct list *red_list;
			struct listnode *node;
			struct bgp_redist *red;

			red_list = bgp->redist[afi][i];
			if (!red_list)
				continue;

			for (ALL_LIST_ELEMENTS_RO(red_list, node, red)) {
				/* "redistribute" configuration.  */
				vty_out(vty, "  redistribute %s",
					zebra_route_string(i));
				if (red->instance)
					vty_out(vty, " %d", red->instance);
				if (red->redist_metric_flag)
					vty_out(vty, " metric %u",
						red->redist_metric);
				if (red->rmap.name)
					vty_out(vty, " route-map %s",
						red->rmap.name);
				vty_out(vty, "\n");
			}
		}
	}
}

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

static bool peergroup_filter_check(struct peer *peer, afi_t afi, safi_t safi,
				   uint8_t type, int direct)
{
	struct bgp_filter *filter;

	if (peer_group_active(peer))
		return !!CHECK_FLAG(peer->filter_override[afi][safi][direct],
				    type);

	filter = &peer->filter[afi][safi];
	switch (type) {
	case PEER_FT_DISTRIBUTE_LIST:
		return !!(filter->dlist[direct].name);
	case PEER_FT_FILTER_LIST:
		return !!(filter->aslist[direct].name);
	case PEER_FT_PREFIX_LIST:
		return !!(filter->plist[direct].name);
	case PEER_FT_ROUTE_MAP:
		return !!(filter->map[direct].name);
	case PEER_FT_UNSUPPRESS_MAP:
		return !!(filter->usmap.name);
	case PEER_FT_ADVERTISE_MAP:
		return !!(filter->advmap.aname
			  && ((filter->advmap.condition == direct)
			      && filter->advmap.cname));
	default:
		return false;
	}
}

/* Return true if the addpath type is set for peer and different from
 * peer-group.
 */
static bool peergroup_af_addpath_check(struct peer *peer, afi_t afi,
				       safi_t safi)
{
	enum bgp_addpath_strat type, g_type;

	type = peer->addpath_type[afi][safi];

	if (type != BGP_ADDPATH_NONE) {
		if (peer_group_active(peer)) {
			g_type = peer->group->conf->addpath_type[afi][safi];

			if (type != g_type)
				return true;
			else
				return false;
		}

		return true;
	}

	return false;
}

/* This is part of the address-family block (unicast only) */
static void bgp_vpn_policy_config_write_afi(struct vty *vty, struct bgp *bgp,
					    afi_t afi)
{
	int indent = 2;
	uint32_t tovpn_sid_index = 0;

	if (bgp->vpn_policy[afi].rmap_name[BGP_VPN_POLICY_DIR_FROMVPN]) {
		if (CHECK_FLAG(bgp->af_flags[afi][SAFI_UNICAST],
			       BGP_CONFIG_VRF_TO_VRF_IMPORT))
			vty_out(vty, "%*simport vrf route-map %s\n", indent, "",
				bgp->vpn_policy[afi]
				.rmap_name[BGP_VPN_POLICY_DIR_FROMVPN]);
		else
			vty_out(vty, "%*sroute-map vpn import %s\n", indent, "",
				bgp->vpn_policy[afi]
				.rmap_name[BGP_VPN_POLICY_DIR_FROMVPN]);
	}
	if (CHECK_FLAG(bgp->af_flags[afi][SAFI_UNICAST],
		       BGP_CONFIG_VRF_TO_VRF_IMPORT)
	    || CHECK_FLAG(bgp->af_flags[afi][SAFI_UNICAST],
			  BGP_CONFIG_VRF_TO_VRF_EXPORT))
		return;

	if (CHECK_FLAG(bgp->vpn_policy[afi].flags,
		BGP_VPN_POLICY_TOVPN_LABEL_AUTO)) {

		vty_out(vty, "%*slabel vpn export %s\n", indent, "", "auto");

	} else {
		if (bgp->vpn_policy[afi].tovpn_label != MPLS_LABEL_NONE) {
			vty_out(vty, "%*slabel vpn export %u\n", indent, "",
				bgp->vpn_policy[afi].tovpn_label);
		}
	}

	if (CHECK_FLAG(bgp->vpn_policy[afi].flags,
		       BGP_VPN_POLICY_TOVPN_LABEL_PER_NEXTHOP))
		vty_out(vty,
			"%*slabel vpn export allocation-mode per-nexthop\n",
			indent, "");

	tovpn_sid_index = bgp->vpn_policy[afi].tovpn_sid_index;
	if (CHECK_FLAG(bgp->vpn_policy[afi].flags,
		       BGP_VPN_POLICY_TOVPN_SID_AUTO)) {
		vty_out(vty, "%*ssid vpn export %s\n", indent, "", "auto");
	} else if (tovpn_sid_index != 0) {
		vty_out(vty, "%*ssid vpn export %d\n", indent, "",
			tovpn_sid_index);
	}

	if (CHECK_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_RD_SET))
		vty_out(vty, "%*srd vpn export %s\n", indent, "",
			bgp->vpn_policy[afi].tovpn_rd_pretty);

	if (CHECK_FLAG(bgp->vpn_policy[afi].flags,
		       BGP_VPN_POLICY_TOVPN_NEXTHOP_SET)) {

		char buf[PREFIX_STRLEN];
		if (inet_ntop(bgp->vpn_policy[afi].tovpn_nexthop.family,
			      &bgp->vpn_policy[afi].tovpn_nexthop.u.prefix, buf,
			      sizeof(buf))) {

			vty_out(vty, "%*snexthop vpn export %s\n",
				indent, "", buf);
		}
	}
	if (bgp->vpn_policy[afi].rtlist[BGP_VPN_POLICY_DIR_FROMVPN]
	    && bgp->vpn_policy[afi].rtlist[BGP_VPN_POLICY_DIR_TOVPN]
	    && ecommunity_cmp(
		       bgp->vpn_policy[afi].rtlist[BGP_VPN_POLICY_DIR_FROMVPN],
		       bgp->vpn_policy[afi].rtlist[BGP_VPN_POLICY_DIR_TOVPN])) {

		char *b = ecommunity_ecom2str(
			bgp->vpn_policy[afi].rtlist[BGP_VPN_POLICY_DIR_TOVPN],
			ECOMMUNITY_FORMAT_ROUTE_MAP, ECOMMUNITY_ROUTE_TARGET);
		vty_out(vty, "%*srt vpn both %s\n", indent, "", b);
		XFREE(MTYPE_ECOMMUNITY_STR, b);
	} else {
		if (bgp->vpn_policy[afi].rtlist[BGP_VPN_POLICY_DIR_FROMVPN]) {
			char *b = ecommunity_ecom2str(
				bgp->vpn_policy[afi]
					.rtlist[BGP_VPN_POLICY_DIR_FROMVPN],
				ECOMMUNITY_FORMAT_ROUTE_MAP,
				ECOMMUNITY_ROUTE_TARGET);
			vty_out(vty, "%*srt vpn import %s\n", indent, "", b);
			XFREE(MTYPE_ECOMMUNITY_STR, b);
		}
		if (bgp->vpn_policy[afi].rtlist[BGP_VPN_POLICY_DIR_TOVPN]) {
			char *b = ecommunity_ecom2str(
				bgp->vpn_policy[afi]
					.rtlist[BGP_VPN_POLICY_DIR_TOVPN],
				ECOMMUNITY_FORMAT_ROUTE_MAP,
				ECOMMUNITY_ROUTE_TARGET);
			vty_out(vty, "%*srt vpn export %s\n", indent, "", b);
			XFREE(MTYPE_ECOMMUNITY_STR, b);
		}
	}

	if (bgp->vpn_policy[afi].rmap_name[BGP_VPN_POLICY_DIR_TOVPN])
		vty_out(vty, "%*sroute-map vpn export %s\n", indent, "",
			bgp->vpn_policy[afi]
				.rmap_name[BGP_VPN_POLICY_DIR_TOVPN]);

	if (bgp->vpn_policy[afi].import_redirect_rtlist) {
		char *b = ecommunity_ecom2str(
					bgp->vpn_policy[afi]
					.import_redirect_rtlist,
					ECOMMUNITY_FORMAT_ROUTE_MAP,
					ECOMMUNITY_ROUTE_TARGET);

		if (bgp->vpn_policy[afi].import_redirect_rtlist->unit_size
		    != ECOMMUNITY_SIZE)
			vty_out(vty, "%*srt6 redirect import %s\n",
				indent, "", b);
		else
			vty_out(vty, "%*srt redirect import %s\n",
				indent, "", b);
		XFREE(MTYPE_ECOMMUNITY_STR, b);
	}
}

static void bgp_config_write_filter(struct vty *vty, struct peer *peer,
				    afi_t afi, safi_t safi)
{
	struct bgp_filter *filter;
	char *addr;

	addr = peer->host;
	filter = &peer->filter[afi][safi];

	/* distribute-list. */
	if (peergroup_filter_check(peer, afi, safi, PEER_FT_DISTRIBUTE_LIST,
				   FILTER_IN))
		vty_out(vty, "  neighbor %s distribute-list %s in\n", addr,
			filter->dlist[FILTER_IN].name);

	if (peergroup_filter_check(peer, afi, safi, PEER_FT_DISTRIBUTE_LIST,
				   FILTER_OUT))
		vty_out(vty, "  neighbor %s distribute-list %s out\n", addr,
			filter->dlist[FILTER_OUT].name);

	/* prefix-list. */
	if (peergroup_filter_check(peer, afi, safi, PEER_FT_PREFIX_LIST,
				   FILTER_IN))
		vty_out(vty, "  neighbor %s prefix-list %s in\n", addr,
			filter->plist[FILTER_IN].name);

	if (peergroup_filter_check(peer, afi, safi, PEER_FT_PREFIX_LIST,
				   FILTER_OUT))
		vty_out(vty, "  neighbor %s prefix-list %s out\n", addr,
			filter->plist[FILTER_OUT].name);

	/* route-map. */
	if (peergroup_filter_check(peer, afi, safi, PEER_FT_ROUTE_MAP, RMAP_IN))
		vty_out(vty, "  neighbor %s route-map %s in\n", addr,
			filter->map[RMAP_IN].name);

	if (peergroup_filter_check(peer, afi, safi, PEER_FT_ROUTE_MAP,
				   RMAP_OUT))
		vty_out(vty, "  neighbor %s route-map %s out\n", addr,
			filter->map[RMAP_OUT].name);

	/* unsuppress-map */
	if (peergroup_filter_check(peer, afi, safi, PEER_FT_UNSUPPRESS_MAP, 0))
		vty_out(vty, "  neighbor %s unsuppress-map %s\n", addr,
			filter->usmap.name);

	/* advertise-map : always applied in OUT direction*/
	if (peergroup_filter_check(peer, afi, safi, PEER_FT_ADVERTISE_MAP,
				   CONDITION_NON_EXIST))
		vty_out(vty,
			"  neighbor %s advertise-map %s non-exist-map %s\n",
			addr, filter->advmap.aname, filter->advmap.cname);

	if (peergroup_filter_check(peer, afi, safi, PEER_FT_ADVERTISE_MAP,
				   CONDITION_EXIST))
		vty_out(vty, "  neighbor %s advertise-map %s exist-map %s\n",
			addr, filter->advmap.aname, filter->advmap.cname);

	/* filter-list. */
	if (peergroup_filter_check(peer, afi, safi, PEER_FT_FILTER_LIST,
				   FILTER_IN))
		vty_out(vty, "  neighbor %s filter-list %s in\n", addr,
			filter->aslist[FILTER_IN].name);

	if (peergroup_filter_check(peer, afi, safi, PEER_FT_FILTER_LIST,
				   FILTER_OUT))
		vty_out(vty, "  neighbor %s filter-list %s out\n", addr,
			filter->aslist[FILTER_OUT].name);
}

/* BGP peer configuration display function. */
static void bgp_config_write_peer_global(struct vty *vty, struct bgp *bgp,
					 struct peer *peer)
{
	struct peer *g_peer = NULL;
	char *addr;
	int if_pg_printed = false;
	int if_ras_printed = false;

	/* Skip dynamic neighbors. */
	if (peer_dynamic_neighbor(peer))
		return;

	if (peer->conf_if)
		addr = peer->conf_if;
	else
		addr = peer->host;

	/************************************
	 ****** Global to the neighbor ******
	 ************************************/
	if (peer->conf_if) {
		if (CHECK_FLAG(peer->flags, PEER_FLAG_IFPEER_V6ONLY))
			vty_out(vty, " neighbor %s interface v6only", addr);
		else
			vty_out(vty, " neighbor %s interface", addr);

		if (peer_group_active(peer)) {
			vty_out(vty, " peer-group %s", peer->group->name);
			if_pg_printed = true;
		} else if (peer->as_type == AS_SPECIFIED) {
			vty_out(vty, " remote-as %s", peer->as_pretty);
			if_ras_printed = true;
		} else if (peer->as_type == AS_INTERNAL) {
			vty_out(vty, " remote-as internal");
			if_ras_printed = true;
		} else if (peer->as_type == AS_EXTERNAL) {
			vty_out(vty, " remote-as external");
			if_ras_printed = true;
		} else if (CHECK_FLAG(peer->as_type, AS_AUTO)) {
			vty_out(vty, " remote-as auto");
			if_ras_printed = true;
		}

		vty_out(vty, "\n");
	}

	/* remote-as and peer-group */
	/* peer is a member of a peer-group */
	if (peer_group_active(peer)) {
		g_peer = peer->group->conf;

		if (g_peer->as_type == AS_UNSPECIFIED && !if_ras_printed) {
			if (peer->as_type == AS_SPECIFIED) {
				vty_out(vty, " neighbor %s remote-as %s\n",
					addr, peer->as_pretty);
			} else if (peer->as_type == AS_INTERNAL) {
				vty_out(vty,
					" neighbor %s remote-as internal\n",
					addr);
			} else if (peer->as_type == AS_EXTERNAL) {
				vty_out(vty,
					" neighbor %s remote-as external\n",
					addr);
			} else if (CHECK_FLAG(peer->as_type, AS_AUTO)) {
				vty_out(vty, " neighbor %s remote-as auto\n",
					addr);
			}
		}

		/* For swpX peers we displayed the peer-group
		 * via 'neighbor swpX interface peer-group PGNAME' */
		if (!if_pg_printed)
			vty_out(vty, " neighbor %s peer-group %s\n", addr,
				peer->group->name);
	}

	/* peer is NOT a member of a peer-group */
	else {
		/* peer is a peer-group, declare the peer-group */
		if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
			vty_out(vty, " neighbor %s peer-group\n", addr);
		}

		if (!if_ras_printed) {
			if (peer->as_type == AS_SPECIFIED) {
				vty_out(vty, " neighbor %s remote-as %s\n",
					addr, peer->as_pretty);
			} else if (peer->as_type == AS_INTERNAL) {
				vty_out(vty,
					" neighbor %s remote-as internal\n",
					addr);
			} else if (peer->as_type == AS_EXTERNAL) {
				vty_out(vty,
					" neighbor %s remote-as external\n",
					addr);
			} else if (CHECK_FLAG(peer->as_type, AS_AUTO)) {
				vty_out(vty, " neighbor %s remote-as auto\n",
					addr);
			}
		}
	}

	/* local-as */
	if (peergroup_flag_check(peer, PEER_FLAG_LOCAL_AS)) {
		vty_out(vty, " neighbor %s local-as %s", addr,
			peer->change_local_as_pretty);
		if (peergroup_flag_check(peer, PEER_FLAG_LOCAL_AS_NO_PREPEND))
			vty_out(vty, " no-prepend");
		if (peergroup_flag_check(peer, PEER_FLAG_LOCAL_AS_REPLACE_AS))
			vty_out(vty, " replace-as");
		if (peergroup_flag_check(peer, PEER_FLAG_DUAL_AS))
			vty_out(vty, " dual-as");
		vty_out(vty, "\n");
	}

	/* description */
	if (peer->desc) {
		vty_out(vty, " neighbor %s description %s\n", addr, peer->desc);
	}

	/* shutdown */
	if (peergroup_flag_check(peer, PEER_FLAG_SHUTDOWN)) {
		if (peer->tx_shutdown_message)
			vty_out(vty, " neighbor %s shutdown message %s\n", addr,
				peer->tx_shutdown_message);
		else
			vty_out(vty, " neighbor %s shutdown\n", addr);
	}

	if (peergroup_flag_check(peer, PEER_FLAG_RTT_SHUTDOWN))
		vty_out(vty, " neighbor %s shutdown rtt %u count %u\n", addr,
			peer->rtt_expected, peer->rtt_keepalive_conf);

	/* bfd */
	if (peer->bfd_config)
		bgp_bfd_peer_config_write(vty, peer, addr);

	/* password */
	if (peergroup_flag_check(peer, PEER_FLAG_PASSWORD))
		vty_out(vty, " neighbor %s password %s\n", addr,
			peer->password);

	/* neighbor solo */
	if (peergroup_flag_check(peer, PEER_FLAG_LONESOUL))
		vty_out(vty, " neighbor %s solo\n", addr);

	/* BGP port */
	if (peer->port != BGP_PORT_DEFAULT) {
		vty_out(vty, " neighbor %s port %d\n", addr, peer->port);
	}

	/* Local interface name */
	if (peer->ifname) {
		vty_out(vty, " neighbor %s interface %s\n", addr, peer->ifname);
	}

	/* TCP max segment size */
	if (CHECK_FLAG(peer->flags, PEER_FLAG_TCP_MSS))
		vty_out(vty, " neighbor %s tcp-mss %d\n", addr, peer->tcp_mss);

	/* passive */
	if (peergroup_flag_check(peer, PEER_FLAG_PASSIVE))
		vty_out(vty, " neighbor %s passive\n", addr);

	/* ebgp-multihop */
	if (peer->sort != BGP_PEER_IBGP && peer->ttl != BGP_DEFAULT_TTL
	    && !(peer->gtsm_hops != BGP_GTSM_HOPS_DISABLED
		 && peer->ttl == MAXTTL)) {
		if (!peer_group_active(peer) || g_peer->ttl != peer->ttl) {
			if (peer->ttl != MAXTTL)
				vty_out(vty, " neighbor %s ebgp-multihop %d\n",
					addr, peer->ttl);
			else
				vty_out(vty, " neighbor %s ebgp-multihop\n",
					addr);
		}
	}

	/* aigp */
	if (peergroup_flag_check(peer, PEER_FLAG_AIGP))
		vty_out(vty, " neighbor %s aigp\n", addr);

	/* graceful-shutdown */
	if (peergroup_flag_check(peer, PEER_FLAG_GRACEFUL_SHUTDOWN))
		vty_out(vty, " neighbor %s graceful-shutdown\n", addr);

	/* role */
	if (peergroup_flag_check(peer, PEER_FLAG_ROLE) &&
	    peer->local_role != ROLE_UNDEFINED)
		vty_out(vty, " neighbor %s local-role %s%s\n", addr,
			bgp_get_name_by_role(peer->local_role),
			CHECK_FLAG(peer->flags, PEER_FLAG_ROLE_STRICT_MODE)
				? " strict-mode"
				: "");

	if (peer->sub_sort == BGP_PEER_EBGP_OAD)
		vty_out(vty, " neighbor %s oad\n", addr);

	/* ttl-security hops */
	if (peer->gtsm_hops != BGP_GTSM_HOPS_DISABLED) {
		if (!peer_group_active(peer)
		    || g_peer->gtsm_hops != peer->gtsm_hops) {
			vty_out(vty, " neighbor %s ttl-security hops %d\n",
				addr, peer->gtsm_hops);
		}
	}

	/* disable-connected-check */
	if (peergroup_flag_check(peer, PEER_FLAG_DISABLE_CONNECTED_CHECK))
		vty_out(vty, " neighbor %s disable-connected-check\n", addr);

	/* link-bw-encoding-ieee */
	if (peergroup_flag_check(peer, PEER_FLAG_DISABLE_LINK_BW_ENCODING_IEEE))
		vty_out(vty, " neighbor %s disable-link-bw-encoding-ieee\n",
			addr);

	if (peergroup_flag_check(peer, PEER_FLAG_EXTENDED_LINK_BANDWIDTH))
		vty_out(vty, " neighbor %s extended-link-bandwidth\n", addr);

	/* extended-optional-parameters */
	if (peergroup_flag_check(peer, PEER_FLAG_EXTENDED_OPT_PARAMS))
		vty_out(vty, " neighbor %s extended-optional-parameters\n",
			addr);

	/* enforce-first-as */
	if (CHECK_FLAG(bgp->flags, BGP_FLAG_ENFORCE_FIRST_AS)) {
		if (!peergroup_flag_check(peer, PEER_FLAG_ENFORCE_FIRST_AS))
			vty_out(vty, " no neighbor %s enforce-first-as\n", addr);
	} else {
		if (peergroup_flag_check(peer, PEER_FLAG_ENFORCE_FIRST_AS))
			vty_out(vty, " neighbor %s enforce-first-as\n", addr);
	}

	/* update-source */
	if (peergroup_flag_check(peer, PEER_FLAG_UPDATE_SOURCE)) {
		if (peer->update_source)
			vty_out(vty, " neighbor %s update-source %pSU\n", addr,
				peer->update_source);
		else if (peer->update_if)
			vty_out(vty, " neighbor %s update-source %s\n", addr,
				peer->update_if);
	}

	/* advertisement-interval */
	if (peergroup_flag_check(peer, PEER_FLAG_ROUTEADV))
		vty_out(vty, " neighbor %s advertisement-interval %u\n", addr,
			peer->routeadv);

	/* timers */
	if (peergroup_flag_check(peer, PEER_FLAG_TIMER))
		vty_out(vty, " neighbor %s timers %u %u\n", addr,
			peer->keepalive, peer->holdtime);

	/* timers connect */
	if (peergroup_flag_check(peer, PEER_FLAG_TIMER_CONNECT))
		vty_out(vty, " neighbor %s timers connect %u\n", addr,
			peer->connect);
	/* need special-case handling for changed default values due to
	 * config profile / version (because there is no "timers bgp connect"
	 * command, we need to save this per-peer :/)
	 */
	else if (!peer_group_active(peer) && !peer->connect &&
		 peer->bgp->default_connect_retry != SAVE_BGP_CONNECT_RETRY)
		vty_out(vty, " neighbor %s timers connect %u\n", addr,
			peer->bgp->default_connect_retry);

	/* timers delayopen */
	if (peergroup_flag_check(peer, PEER_FLAG_TIMER_DELAYOPEN))
		vty_out(vty, " neighbor %s timers delayopen %u\n", addr,
			peer->delayopen);
	/* Save config even though flag is not set if default values have been
	 * changed
	 */
	else if (!peer_group_active(peer) && !peer->delayopen
		 && peer->bgp->default_delayopen != BGP_DEFAULT_DELAYOPEN)
		vty_out(vty, " neighbor %s timers delayopen %u\n", addr,
			peer->bgp->default_delayopen);

	/* capability software-version */
	if (CHECK_FLAG(bgp->flags, BGP_FLAG_DYNAMIC_CAPABILITY)) {
		if (!peergroup_flag_check(peer, PEER_FLAG_DYNAMIC_CAPABILITY))
			vty_out(vty, " no neighbor %s capability dynamic\n",
				addr);
	} else {
		if (peergroup_flag_check(peer, PEER_FLAG_DYNAMIC_CAPABILITY))
			vty_out(vty, " neighbor %s capability dynamic\n", addr);
	}

	/* capability extended-nexthop */
	if (peergroup_flag_check(peer, PEER_FLAG_CAPABILITY_ENHE)) {
		if (CHECK_FLAG(peer->flags_invert, PEER_FLAG_CAPABILITY_ENHE) &&
		    !peer->conf_if)
			vty_out(vty,
				" no neighbor %s capability extended-nexthop\n",
				addr);
		else if (!peer->conf_if)
			vty_out(vty,
				" neighbor %s capability extended-nexthop\n",
				addr);
	}

	/* capability software-version */
	if (CHECK_FLAG(bgp->flags, BGP_FLAG_SOFT_VERSION_CAPABILITY)) {
		if (!peergroup_flag_check(peer,
					  PEER_FLAG_CAPABILITY_SOFT_VERSION))
			vty_out(vty,
				" no neighbor %s capability software-version\n",
				addr);
	} else {
		if (peergroup_flag_check(peer,
					 PEER_FLAG_CAPABILITY_SOFT_VERSION))
			vty_out(vty,
				" neighbor %s capability software-version\n",
				addr);
	}

	/* dont-capability-negotiation */
	if (peergroup_flag_check(peer, PEER_FLAG_DONT_CAPABILITY))
		vty_out(vty, " neighbor %s dont-capability-negotiate\n", addr);

	/* capability fqdn */
	if (peergroup_flag_check(peer, PEER_FLAG_CAPABILITY_FQDN))
		vty_out(vty,
			" no neighbor %s capability fqdn\n",
			addr);

	/* override-capability */
	if (peergroup_flag_check(peer, PEER_FLAG_OVERRIDE_CAPABILITY))
		vty_out(vty, " neighbor %s override-capability\n", addr);

	/* strict-capability-match */
	if (peergroup_flag_check(peer, PEER_FLAG_STRICT_CAP_MATCH))
		vty_out(vty, " neighbor %s strict-capability-match\n", addr);

	/* Sender side AS path loop detection. */
	if (peergroup_flag_check(peer, PEER_FLAG_AS_LOOP_DETECTION))
		vty_out(vty, " neighbor %s sender-as-path-loop-detection\n",
			addr);

	/* path-attribute discard */
	char discard_attrs_str[BUFSIZ] = {0};
	bool discard_attrs = bgp_path_attribute_discard(
		peer, discard_attrs_str, sizeof(discard_attrs_str));

	if (discard_attrs)
		vty_out(vty, " neighbor %s path-attribute discard %s\n", addr,
			discard_attrs_str);

	/* path-attribute treat-as-withdraw */
	char withdraw_attrs_str[BUFSIZ] = {0};
	bool withdraw_attrs = bgp_path_attribute_treat_as_withdraw(
		peer, withdraw_attrs_str, sizeof(withdraw_attrs_str));

	if (withdraw_attrs)
		vty_out(vty,
			" neighbor %s path-attribute treat-as-withdraw %s\n",
			addr, withdraw_attrs_str);

	if (!CHECK_FLAG(peer->peer_gr_new_status_flag,
			PEER_GRACEFUL_RESTART_NEW_STATE_INHERIT)) {

		if (CHECK_FLAG(peer->peer_gr_new_status_flag,
			       PEER_GRACEFUL_RESTART_NEW_STATE_HELPER)) {
			vty_out(vty,
				" neighbor %s graceful-restart-helper\n", addr);
		} else if (CHECK_FLAG(
				   peer->peer_gr_new_status_flag,
				   PEER_GRACEFUL_RESTART_NEW_STATE_RESTART)) {
			vty_out(vty,
				" neighbor %s graceful-restart\n", addr);
		} else if (
			(!(CHECK_FLAG(peer->peer_gr_new_status_flag,
				      PEER_GRACEFUL_RESTART_NEW_STATE_HELPER))
			 && !(CHECK_FLAG(
				 peer->peer_gr_new_status_flag,
				 PEER_GRACEFUL_RESTART_NEW_STATE_RESTART)))) {
			vty_out(vty, " neighbor %s graceful-restart-disable\n",
				addr);
		}
	}
}

/* BGP peer configuration display function. */
static void bgp_config_write_peer_af(struct vty *vty, struct bgp *bgp,
				     struct peer *peer, afi_t afi, safi_t safi)
{
	struct peer *g_peer = NULL;
	char *addr;
	bool flag_scomm, flag_secomm, flag_slcomm;

	/* skip hidden default vrf bgp instance */
	if (IS_BGP_INSTANCE_HIDDEN(bgp))
		return;

	/* Skip dynamic neighbors. */
	if (peer_dynamic_neighbor(peer))
		return;

	if (peer->conf_if)
		addr = peer->conf_if;
	else
		addr = peer->host;

	/************************************
	 ****** Per AF to the neighbor ******
	 ************************************/
	if (peer_group_active(peer)) {
		g_peer = peer->group->conf;

		/* If the peer-group is active but peer is not, print a 'no
		 * activate' */
		if (g_peer->afc[afi][safi] && !peer->afc[afi][safi]) {
			vty_out(vty, "  no neighbor %s activate\n", addr);
		}

		/* If the peer-group is not active but peer is, print an
		   'activate' */
		else if (!g_peer->afc[afi][safi] && peer->afc[afi][safi]) {
			vty_out(vty, "  neighbor %s activate\n", addr);
		}
	} else {
		if (peer->afc[afi][safi]) {
			if (safi == SAFI_ENCAP)
				vty_out(vty, "  neighbor %s activate\n", addr);
			else if (!bgp->default_af[afi][safi])
				vty_out(vty, "  neighbor %s activate\n", addr);
		} else {
			if (bgp->default_af[afi][safi])
				vty_out(vty, "  no neighbor %s activate\n",
					addr);
		}
	}

	/* addpath TX knobs */
	if (peergroup_af_addpath_check(peer, afi, safi)) {
		switch (peer->addpath_type[afi][safi]) {
		case BGP_ADDPATH_ALL:
			vty_out(vty, "  neighbor %s addpath-tx-all-paths\n",
				addr);
			break;
		case BGP_ADDPATH_BEST_PER_AS:
			vty_out(vty,
				"  neighbor %s addpath-tx-bestpath-per-AS\n",
				addr);
			break;
		case BGP_ADDPATH_BEST_SELECTED:
			if (peer->addpath_best_selected[afi][safi])
				vty_out(vty,
					"  neighbor %s addpath-tx-best-selected %u\n",
					addr,
					peer->addpath_best_selected[afi][safi]);
			break;
		case BGP_ADDPATH_MAX:
		case BGP_ADDPATH_NONE:
			break;
		}
	}

	if (CHECK_FLAG(peer->af_flags[afi][safi], PEER_FLAG_DISABLE_ADDPATH_RX))
		vty_out(vty, "  neighbor %s disable-addpath-rx\n", addr);

	if (CHECK_FLAG(peer->af_flags[afi][safi],
		       PEER_FLAG_ADDPATH_RX_PATHS_LIMIT))
		vty_out(vty, "  neighbor %s addpath-rx-paths-limit %u\n", addr,
			peer->addpath_paths_limit[afi][safi].send);

	/* ORF capability.  */
	if (peergroup_af_flag_check(peer, afi, safi, PEER_FLAG_ORF_PREFIX_SM)
	    || peergroup_af_flag_check(peer, afi, safi,
				       PEER_FLAG_ORF_PREFIX_RM)) {
		vty_out(vty, "  neighbor %s capability orf prefix-list", addr);

		if (peergroup_af_flag_check(peer, afi, safi,
					    PEER_FLAG_ORF_PREFIX_SM)
		    && peergroup_af_flag_check(peer, afi, safi,
					       PEER_FLAG_ORF_PREFIX_RM))
			vty_out(vty, " both");
		else if (peergroup_af_flag_check(peer, afi, safi,
						 PEER_FLAG_ORF_PREFIX_SM))
			vty_out(vty, " send");
		else
			vty_out(vty, " receive");
		vty_out(vty, "\n");
	}

	/* Route reflector client. */
	if (peergroup_af_flag_check(peer, afi, safi,
				    PEER_FLAG_REFLECTOR_CLIENT)) {
		vty_out(vty, "  neighbor %s route-reflector-client\n", addr);
	}

	/* next-hop-self force */
	if (peergroup_af_flag_check(peer, afi, safi,
				    PEER_FLAG_FORCE_NEXTHOP_SELF)) {
		vty_out(vty, "  neighbor %s next-hop-self force\n", addr);
	}

	/* next-hop-self */
	if (peergroup_af_flag_check(peer, afi, safi, PEER_FLAG_NEXTHOP_SELF)) {
		vty_out(vty, "  neighbor %s next-hop-self\n", addr);
	}

	/* remove-private-AS */
	if (peergroup_af_flag_check(peer, afi, safi,
				    PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE)) {
		vty_out(vty, "  neighbor %s remove-private-AS all replace-AS\n",
			addr);
	}

	else if (peergroup_af_flag_check(peer, afi, safi,
					 PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE)) {
		vty_out(vty, "  neighbor %s remove-private-AS replace-AS\n",
			addr);
	}

	else if (peergroup_af_flag_check(peer, afi, safi,
					 PEER_FLAG_REMOVE_PRIVATE_AS_ALL)) {
		vty_out(vty, "  neighbor %s remove-private-AS all\n", addr);
	}

	else if (peergroup_af_flag_check(peer, afi, safi,
					 PEER_FLAG_REMOVE_PRIVATE_AS)) {
		vty_out(vty, "  neighbor %s remove-private-AS\n", addr);
	}

	/* as-override */
	if (peergroup_af_flag_check(peer, afi, safi, PEER_FLAG_AS_OVERRIDE)) {
		vty_out(vty, "  neighbor %s as-override\n", addr);
	}

	/* send-community print. */
	flag_scomm = peergroup_af_flag_check(peer, afi, safi,
					     PEER_FLAG_SEND_COMMUNITY);
	flag_secomm = peergroup_af_flag_check(peer, afi, safi,
					      PEER_FLAG_SEND_EXT_COMMUNITY);
	flag_slcomm = peergroup_af_flag_check(peer, afi, safi,
					      PEER_FLAG_SEND_LARGE_COMMUNITY);

	if (flag_scomm && flag_secomm && flag_slcomm) {
		vty_out(vty, "  no neighbor %s send-community all\n", addr);
	} else {
		if (flag_scomm)
			vty_out(vty, "  no neighbor %s send-community\n", addr);
		if (flag_secomm)
			vty_out(vty,
				"  no neighbor %s send-community extended\n",
				addr);

		if (flag_slcomm)
			vty_out(vty, "  no neighbor %s send-community large\n",
				addr);

		if (peergroup_af_flag_check(peer, afi, safi,
					    PEER_FLAG_SEND_EXT_COMMUNITY_RPKI))
			vty_out(vty,
				"  no neighbor %s send-community extended rpki\n",
				addr);
	}

	/* Default information */
	if (peergroup_af_flag_check(peer, afi, safi,
				    PEER_FLAG_DEFAULT_ORIGINATE)) {
		vty_out(vty, "  neighbor %s default-originate", addr);

		if (peer->default_rmap[afi][safi].name)
			vty_out(vty, " route-map %s",
				peer->default_rmap[afi][safi].name);

		vty_out(vty, "\n");
	}

	/* Soft reconfiguration inbound. */
	if (peergroup_af_flag_check(peer, afi, safi, PEER_FLAG_SOFT_RECONFIG)) {
		vty_out(vty, "  neighbor %s soft-reconfiguration inbound\n",
			addr);
	}

	/* maximum-prefix. */
	if (peergroup_af_flag_check(peer, afi, safi, PEER_FLAG_MAX_PREFIX)) {
		vty_out(vty, "  neighbor %s maximum-prefix %u", addr,
			peer->pmax[afi][safi]);

		if (peer->pmax_threshold[afi][safi]
		    != MAXIMUM_PREFIX_THRESHOLD_DEFAULT)
			vty_out(vty, " %u", peer->pmax_threshold[afi][safi]);
		if (peer_af_flag_check(peer, afi, safi,
				       PEER_FLAG_MAX_PREFIX_WARNING))
			vty_out(vty, " warning-only");
		if (peer->pmax_restart[afi][safi])
			vty_out(vty, " restart %u",
				peer->pmax_restart[afi][safi]);
		if (peer_af_flag_check(peer, afi, safi,
				       PEER_FLAG_MAX_PREFIX_FORCE))
			vty_out(vty, " force");

		vty_out(vty, "\n");
	}

	/* maximum-prefix-out */
	if (peergroup_af_flag_check(peer, afi, safi, PEER_FLAG_MAX_PREFIX_OUT))
		vty_out(vty, "  neighbor %s maximum-prefix-out %u\n",
			addr, peer->pmax_out[afi][safi]);

	/* Route server client. */
	if (peergroup_af_flag_check(peer, afi, safi,
				    PEER_FLAG_RSERVER_CLIENT)) {
		vty_out(vty, "  neighbor %s route-server-client\n", addr);
	}

	/* Nexthop-local unchanged. */
	if (peergroup_af_flag_check(peer, afi, safi,
				    PEER_FLAG_NEXTHOP_LOCAL_UNCHANGED)) {
		vty_out(vty, "  neighbor %s nexthop-local unchanged\n", addr);
	}

	/* allowas-in <1-10> */
	if (peergroup_af_flag_check(peer, afi, safi, PEER_FLAG_ALLOWAS_IN)) {
		if (peer_af_flag_check(peer, afi, safi,
				       PEER_FLAG_ALLOWAS_IN_ORIGIN)) {
			vty_out(vty, "  neighbor %s allowas-in origin\n", addr);
		} else if (peer->allowas_in[afi][safi] == 3) {
			vty_out(vty, "  neighbor %s allowas-in\n", addr);
		} else {
			vty_out(vty, "  neighbor %s allowas-in %d\n", addr,
				peer->allowas_in[afi][safi]);
		}
	}

	/* accept-own */
	if (peergroup_af_flag_check(peer, afi, safi, PEER_FLAG_ACCEPT_OWN))
		vty_out(vty, "  neighbor %s accept-own\n", addr);

	/* soo */
	if (peergroup_af_flag_check(peer, afi, safi, PEER_FLAG_SOO)) {
		char *soo_str = ecommunity_ecom2str(
			peer->soo[afi][safi], ECOMMUNITY_FORMAT_ROUTE_MAP, 0);

		vty_out(vty, "  neighbor %s soo %s\n", addr, soo_str);
		XFREE(MTYPE_ECOMMUNITY_STR, soo_str);
	}

	/* weight */
	if (peergroup_af_flag_check(peer, afi, safi, PEER_FLAG_WEIGHT))
		vty_out(vty, "  neighbor %s weight %lu\n", addr,
			peer->weight[afi][safi]);

	/* Filter. */
	bgp_config_write_filter(vty, peer, afi, safi);

	/* atribute-unchanged. */
	if (peer_af_flag_check(peer, afi, safi, PEER_FLAG_AS_PATH_UNCHANGED)
	    || (safi != SAFI_EVPN
		&& peer_af_flag_check(peer, afi, safi,
				      PEER_FLAG_NEXTHOP_UNCHANGED))
	    || peer_af_flag_check(peer, afi, safi, PEER_FLAG_MED_UNCHANGED)) {

		if (!peer_group_active(peer)
		    || peergroup_af_flag_check(peer, afi, safi,
					       PEER_FLAG_AS_PATH_UNCHANGED)
		    || peergroup_af_flag_check(peer, afi, safi,
					       PEER_FLAG_NEXTHOP_UNCHANGED)
		    || peergroup_af_flag_check(peer, afi, safi,
					       PEER_FLAG_MED_UNCHANGED)) {

			vty_out(vty,
				"  neighbor %s attribute-unchanged%s%s%s\n",
				addr,
				peer_af_flag_check(peer, afi, safi,
						   PEER_FLAG_AS_PATH_UNCHANGED)
					? " as-path"
					: "",
				peer_af_flag_check(peer, afi, safi,
						   PEER_FLAG_NEXTHOP_UNCHANGED)
					? " next-hop"
					: "",
				peer_af_flag_check(peer, afi, safi,
						   PEER_FLAG_MED_UNCHANGED)
					? " med"
					: "");
		}
	}
}

static void bgp_vpn_config_write(struct vty *vty, struct bgp *bgp, afi_t afi,
				 safi_t safi)
{
	if (!CHECK_FLAG(bgp->af_flags[afi][safi],
			BGP_VPNVX_RETAIN_ROUTE_TARGET_ALL))
		vty_out(vty, "  no bgp retain route-target all\n");
}

/* Address family based peer configuration display.  */
static void bgp_config_write_family(struct vty *vty, struct bgp *bgp, afi_t afi,
				    safi_t safi)
{
	struct peer *peer;
	struct peer_group *group;
	struct listnode *node, *nnode;

	/* skip hidden default vrf bgp instance */
	if (IS_BGP_INSTANCE_HIDDEN(bgp))
		return;

	vty_frame(vty, " !\n address-family ");
	if (afi == AFI_IP) {
		if (safi == SAFI_UNICAST)
			vty_frame(vty, "ipv4 unicast");
		else if (safi == SAFI_LABELED_UNICAST)
			vty_frame(vty, "ipv4 labeled-unicast");
		else if (safi == SAFI_MULTICAST)
			vty_frame(vty, "ipv4 multicast");
		else if (safi == SAFI_MPLS_VPN)
			vty_frame(vty, "ipv4 vpn");
		else if (safi == SAFI_ENCAP)
			vty_frame(vty, "ipv4 encap");
		else if (safi == SAFI_FLOWSPEC)
			vty_frame(vty, "ipv4 flowspec");
	} else if (afi == AFI_IP6) {
		if (safi == SAFI_UNICAST)
			vty_frame(vty, "ipv6 unicast");
		else if (safi == SAFI_LABELED_UNICAST)
			vty_frame(vty, "ipv6 labeled-unicast");
		else if (safi == SAFI_MULTICAST)
			vty_frame(vty, "ipv6 multicast");
		else if (safi == SAFI_MPLS_VPN)
			vty_frame(vty, "ipv6 vpn");
		else if (safi == SAFI_ENCAP)
			vty_frame(vty, "ipv6 encap");
		else if (safi == SAFI_FLOWSPEC)
			vty_frame(vty, "ipv6 flowspec");
	} else if (afi == AFI_L2VPN) {
		if (safi == SAFI_EVPN)
			vty_frame(vty, "l2vpn evpn");
	}
	vty_frame(vty, "\n");

	bgp_config_write_distance(vty, bgp, afi, safi);

	bgp_config_write_network(vty, bgp, afi, safi);

	bgp_config_write_redistribute(vty, bgp, afi, safi);

	/* BGP flag dampening. */
	if (CHECK_FLAG(bgp->af_flags[afi][safi], BGP_CONFIG_DAMPENING))
		bgp_config_write_damp(vty, bgp, afi, safi);
	for (ALL_LIST_ELEMENTS_RO(bgp->group, node, group))
		if (peer_af_flag_check(group->conf, afi, safi,
				       PEER_FLAG_CONFIG_DAMPENING))
			bgp_config_write_peer_damp(vty, group->conf, afi, safi);
	for (ALL_LIST_ELEMENTS_RO(bgp->peer, node, peer))
		if (CHECK_FLAG(peer->flags, PEER_FLAG_CONFIG_NODE) &&
		    peer_af_flag_check(peer, afi, safi,
				       PEER_FLAG_CONFIG_DAMPENING))
			bgp_config_write_peer_damp(vty, peer, afi, safi);

	for (ALL_LIST_ELEMENTS(bgp->group, node, nnode, group))
		bgp_config_write_peer_af(vty, bgp, group->conf, afi, safi);

	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
		/* Do not display doppelganger peers */
		if (CHECK_FLAG(peer->flags, PEER_FLAG_CONFIG_NODE))
			bgp_config_write_peer_af(vty, bgp, peer, afi, safi);
	}

	bgp_config_write_maxpaths(vty, bgp, afi, safi);
	bgp_config_write_table_map(vty, bgp, afi, safi);

	if (safi == SAFI_EVPN)
		bgp_config_write_evpn_info(vty, bgp, afi, safi);

	if (safi == SAFI_FLOWSPEC)
		bgp_fs_config_write_pbr(vty, bgp, afi, safi);

	if (safi == SAFI_MPLS_VPN)
		bgp_vpn_config_write(vty, bgp, afi, safi);

	if (safi == SAFI_UNICAST) {
		bgp_vpn_policy_config_write_afi(vty, bgp, afi);
		if (CHECK_FLAG(bgp->af_flags[afi][safi],
			       BGP_CONFIG_VRF_TO_MPLSVPN_EXPORT)) {

			vty_out(vty, "  export vpn\n");
		}
		if (CHECK_FLAG(bgp->af_flags[afi][safi],
			       BGP_CONFIG_MPLSVPN_TO_VRF_IMPORT)) {

			vty_out(vty, "  import vpn\n");
		}
		if (CHECK_FLAG(bgp->af_flags[afi][safi],
			       BGP_CONFIG_VRF_TO_VRF_IMPORT)) {
			char *name;

			for (ALL_LIST_ELEMENTS_RO(
				     bgp->vpn_policy[afi].import_vrf, node,
				     name))
				vty_out(vty, "  import vrf %s\n", name);
		}
	}

	vty_endframe(vty, " exit-address-family\n");
}

int bgp_config_write(struct vty *vty)
{
	struct bgp *bgp;
	struct peer_group *group;
	struct peer *peer;
	struct listnode *node, *nnode;
	struct listnode *mnode, *mnnode;
	afi_t afi;
	safi_t safi;
	uint32_t tovpn_sid_index = 0;

	hook_call(bgp_snmp_traps_config_write, vty);

	vty_out(vty, "!\n");
	if (bm->rmap_update_timer != RMAP_DEFAULT_UPDATE_TIMER)
		vty_out(vty, "bgp route-map delay-timer %u\n",
			bm->rmap_update_timer);

	if (bm->v_update_delay != BGP_UPDATE_DELAY_DEFAULT) {
		vty_out(vty, "bgp update-delay %d", bm->v_update_delay);
		if (bm->v_update_delay != bm->v_establish_wait)
			vty_out(vty, " %d", bm->v_establish_wait);
		vty_out(vty, "\n");
	}

	if (bm->wait_for_fib)
		vty_out(vty, "bgp suppress-fib-pending\n");

	if (bm->stalepath_time != BGP_DEFAULT_STALEPATH_TIME)
		vty_out(vty, "bgp graceful-restart stalepath-time %u\n",
			bm->stalepath_time);

	if (bm->restart_time != BGP_DEFAULT_RESTART_TIME)
		vty_out(vty, "bgp graceful-restart restart-time %u\n",
			bm->restart_time);

	if (bm->select_defer_time != BGP_DEFAULT_SELECT_DEFERRAL_TIME)
		vty_out(vty, "bgp graceful-restart select-defer-time %u\n",
			bm->select_defer_time);

	if (CHECK_FLAG(bm->flags, BM_FLAG_GR_RESTARTER))
		vty_out(vty, "bgp graceful-restart\n");
	else if (CHECK_FLAG(bm->flags, BM_FLAG_GR_DISABLED))
		vty_out(vty, "bgp graceful-restart-disable\n");

	if (CHECK_FLAG(bm->flags, BM_FLAG_GR_PRESERVE_FWD))
		vty_out(vty, "bgp graceful-restart preserve-fw-state\n");

	if (bm->rib_stale_time != BGP_DEFAULT_RIB_STALE_TIME)
		vty_out(vty, "bgp graceful-restart rib-stale-time %u\n",
			bm->rib_stale_time);

	if (CHECK_FLAG(bm->flags, BM_FLAG_GRACEFUL_SHUTDOWN))
		vty_out(vty, "bgp graceful-shutdown\n");

	/* No-RIB (Zebra) option flag configuration */
	if (bgp_option_check(BGP_OPT_NO_FIB))
		vty_out(vty, "bgp no-rib\n");

	if (CHECK_FLAG(bm->flags, BM_FLAG_SEND_EXTRA_DATA_TO_ZEBRA))
		vty_out(vty, "bgp send-extra-data zebra\n");

	if (CHECK_FLAG(bm->flags, BM_FLAG_IPV6_NO_AUTO_RA))
		vty_out(vty, "no bgp ipv6-auto-ra\n");

	/* DSCP value for outgoing packets in BGP connections */
	if (bm->ip_tos != IPTOS_PREC_INTERNETCONTROL)
		vty_out(vty, "bgp session-dscp %u\n", bm->ip_tos >> 2);

	/* BGP InQ limit */
	if (bm->inq_limit != BM_DEFAULT_Q_LIMIT)
		vty_out(vty, "bgp input-queue-limit %u\n", bm->inq_limit);

	if (bm->outq_limit != BM_DEFAULT_Q_LIMIT)
		vty_out(vty, "bgp output-queue-limit %u\n", bm->outq_limit);

	vty_out(vty, "!\n");

	/* BGP configuration. */
	for (ALL_LIST_ELEMENTS(bm->bgp, mnode, mnnode, bgp)) {

		/* skip all auto created vrf as they dont have user config */
		if (CHECK_FLAG(bgp->vrf_flags, BGP_VRF_AUTO))
			continue;

		/* skip hidden default vrf bgp instance */
		if (IS_BGP_INSTANCE_HIDDEN(bgp))
			continue;

		/* Router bgp ASN */
		vty_out(vty, "router bgp %s", bgp->as_pretty);

		if (bgp->name)
			vty_out(vty, " %s %s",
				(bgp->inst_type  == BGP_INSTANCE_TYPE_VIEW)
				? "view" : "vrf", bgp->name);
		if (CHECK_FLAG(bgp->config, BGP_CONFIG_ASNOTATION))
			vty_out(vty, " as-notation %s",
				asn_mode2str(bgp->asnotation));

		vty_out(vty, "\n");

		/* BGP fast-external-failover. */
		if (CHECK_FLAG(bgp->flags, BGP_FLAG_NO_FAST_EXT_FAILOVER))
			vty_out(vty, " no bgp fast-external-failover\n");

		/* BGP router ID. */
		if (bgp->router_id_static.s_addr != INADDR_ANY)
			vty_out(vty, " bgp router-id %pI4\n",
				&bgp->router_id_static);

		/* Suppress fib pending */
		if (CHECK_FLAG(bgp->flags, BGP_FLAG_SUPPRESS_FIB_PENDING))
			vty_out(vty, " bgp suppress-fib-pending\n");

		/* BGP log-neighbor-changes. */
		if (!!CHECK_FLAG(bgp->flags, BGP_FLAG_LOG_NEIGHBOR_CHANGES)
		    != SAVE_BGP_LOG_NEIGHBOR_CHANGES)
			vty_out(vty, " %sbgp log-neighbor-changes\n",
				CHECK_FLAG(bgp->flags,
					   BGP_FLAG_LOG_NEIGHBOR_CHANGES)
					? ""
					: "no ");

		/* BGP configuration. */
		if (CHECK_FLAG(bgp->flags, BGP_FLAG_ALWAYS_COMPARE_MED))
			vty_out(vty, " bgp always-compare-med\n");

		/* RFC8212 default eBGP policy. */
		if (!!CHECK_FLAG(bgp->flags, BGP_FLAG_EBGP_REQUIRES_POLICY)
		    != SAVE_BGP_EBGP_REQUIRES_POLICY)
			vty_out(vty, " %sbgp ebgp-requires-policy\n",
				CHECK_FLAG(bgp->flags,
					   BGP_FLAG_EBGP_REQUIRES_POLICY)
					? ""
					: "no ");

		/* bgp enforce-first-as */
		if (!!CHECK_FLAG(bgp->flags, BGP_FLAG_ENFORCE_FIRST_AS) !=
		    SAVE_BGP_ENFORCE_FIRST_AS)
			vty_out(vty, " %sbgp enforce-first-as\n",
				CHECK_FLAG(bgp->flags,
					   BGP_FLAG_ENFORCE_FIRST_AS)
					? ""
					: "no ");

		if (!!CHECK_FLAG(bgp->flags, BGP_FLAG_LU_IPV4_EXPLICIT_NULL) &&
		    !!CHECK_FLAG(bgp->flags, BGP_FLAG_LU_IPV6_EXPLICIT_NULL))
			vty_out(vty, " bgp labeled-unicast explicit-null\n");
		else if (!!CHECK_FLAG(bgp->flags,
				      BGP_FLAG_LU_IPV4_EXPLICIT_NULL))
			vty_out(vty,
				" bgp labeled-unicast ipv4-explicit-null\n");
		else if (!!CHECK_FLAG(bgp->flags,
				      BGP_FLAG_LU_IPV6_EXPLICIT_NULL))
			vty_out(vty,
				" bgp labeled-unicast ipv6-explicit-null\n");

		/* draft-ietf-idr-deprecate-as-set-confed-set */
		if (bgp->reject_as_sets)
			vty_out(vty, " bgp reject-as-sets\n");

		/* Suppress duplicate updates if the route actually not changed
		 */
		if (!!CHECK_FLAG(bgp->flags, BGP_FLAG_SUPPRESS_DUPLICATES)
		    != SAVE_BGP_SUPPRESS_DUPLICATES)
			vty_out(vty, " %sbgp suppress-duplicates\n",
				CHECK_FLAG(bgp->flags,
					   BGP_FLAG_SUPPRESS_DUPLICATES)
					? ""
					: "no ");

		/* Send Hard Reset CEASE Notification for 'Administrative Reset'
		 */
		if (!!CHECK_FLAG(bgp->flags, BGP_FLAG_HARD_ADMIN_RESET) !=
		    SAVE_BGP_HARD_ADMIN_RESET)
			vty_out(vty, " %sbgp hard-administrative-reset\n",
				CHECK_FLAG(bgp->flags,
					   BGP_FLAG_HARD_ADMIN_RESET)
					? ""
					: "no ");

		/* BGP default <afi>-<safi> */
		FOREACH_AFI_SAFI (afi, safi) {
			if (afi == AFI_IP && safi == SAFI_UNICAST) {
				if (!bgp->default_af[afi][safi])
					vty_out(vty, " no bgp default %s\n",
						get_bgp_default_af_flag(afi,
									safi));
			} else if (bgp->default_af[afi][safi])
				vty_out(vty, " bgp default %s\n",
					get_bgp_default_af_flag(afi, safi));
		}

		/* BGP default local-preference. */
		if (bgp->default_local_pref != BGP_DEFAULT_LOCAL_PREF)
			vty_out(vty, " bgp default local-preference %u\n",
				bgp->default_local_pref);

		/* BGP default show-hostname */
		if (!!CHECK_FLAG(bgp->flags, BGP_FLAG_SHOW_HOSTNAME)
		    != SAVE_BGP_SHOW_HOSTNAME)
			vty_out(vty, " %sbgp default show-hostname\n",
				CHECK_FLAG(bgp->flags, BGP_FLAG_SHOW_HOSTNAME)
					? ""
					: "no ");

		/* BGP default show-nexthop-hostname */
		if (!!CHECK_FLAG(bgp->flags, BGP_FLAG_SHOW_NEXTHOP_HOSTNAME)
		    != SAVE_BGP_SHOW_HOSTNAME)
			vty_out(vty, " %sbgp default show-nexthop-hostname\n",
				CHECK_FLAG(bgp->flags,
					   BGP_FLAG_SHOW_NEXTHOP_HOSTNAME)
					? ""
					: "no ");

		if (!!CHECK_FLAG(bgp->flags, BGP_FLAG_SOFT_VERSION_CAPABILITY) !=
		    SAVE_BGP_SOFT_VERSION_CAPABILITY)
			vty_out(vty,
				" %sbgp default software-version-capability\n",
				CHECK_FLAG(bgp->flags,
					   BGP_FLAG_SOFT_VERSION_CAPABILITY)
					? ""
					: "no ");

		if (!!CHECK_FLAG(bgp->flags, BGP_FLAG_DYNAMIC_CAPABILITY) !=
		    SAVE_BGP_DYNAMIC_CAPABILITY)
			vty_out(vty,
				" %sbgp default dynamic-capability\n",
				CHECK_FLAG(bgp->flags,
					   BGP_FLAG_DYNAMIC_CAPABILITY)
					? ""
					: "no ");

		/* BGP default subgroup-pkt-queue-max. */
		if (bgp->default_subgroup_pkt_queue_max
		    != BGP_DEFAULT_SUBGROUP_PKT_QUEUE_MAX)
			vty_out(vty, " bgp default subgroup-pkt-queue-max %u\n",
				bgp->default_subgroup_pkt_queue_max);

		/* BGP client-to-client reflection. */
		if (CHECK_FLAG(bgp->flags, BGP_FLAG_NO_CLIENT_TO_CLIENT))
			vty_out(vty, " no bgp client-to-client reflection\n");

		/* BGP cluster ID. */
		if (CHECK_FLAG(bgp->config, BGP_CONFIG_CLUSTER_ID))
			vty_out(vty, " bgp cluster-id %pI4\n",
				&bgp->cluster_id);

		/* Disable ebgp connected nexthop check */
		if (CHECK_FLAG(bgp->flags, BGP_FLAG_DISABLE_NH_CONNECTED_CHK))
			vty_out(vty,
				" bgp disable-ebgp-connected-route-check\n");

		/* Confederation identifier*/
		if (CHECK_FLAG(bgp->config, BGP_CONFIG_CONFEDERATION))
			vty_out(vty, " bgp confederation identifier %s\n",
				bgp->confed_id_pretty);

		/* Confederation peer */
		if (bgp->confed_peers_cnt > 0) {
			int i;

			vty_out(vty, " bgp confederation peers");

			for (i = 0; i < bgp->confed_peers_cnt; i++)
				vty_out(vty, " %s",
					bgp->confed_peers[i].as_pretty);

			vty_out(vty, "\n");
		}

		/* BGP deterministic-med. */
		if (!!CHECK_FLAG(bgp->flags, BGP_FLAG_DETERMINISTIC_MED)
		    != SAVE_BGP_DETERMINISTIC_MED)
			vty_out(vty, " %sbgp deterministic-med\n",
				CHECK_FLAG(bgp->flags,
					   BGP_FLAG_DETERMINISTIC_MED)
					? ""
					: "no ");

		/* BGP update-delay. */
		bgp_config_write_update_delay(vty, bgp);

		if (bgp->v_maxmed_onstartup
		    != BGP_MAXMED_ONSTARTUP_UNCONFIGURED) {
			vty_out(vty, " bgp max-med on-startup %u",
				bgp->v_maxmed_onstartup);
			if (bgp->maxmed_onstartup_value
			    != BGP_MAXMED_VALUE_DEFAULT)
				vty_out(vty, " %u",
					bgp->maxmed_onstartup_value);
			vty_out(vty, "\n");
		}
		if (bgp->v_maxmed_admin != BGP_MAXMED_ADMIN_UNCONFIGURED) {
			vty_out(vty, " bgp max-med administrative");
			if (bgp->maxmed_admin_value != BGP_MAXMED_VALUE_DEFAULT)
				vty_out(vty, " %u", bgp->maxmed_admin_value);
			vty_out(vty, "\n");
		}

		/* write quanta */
		bgp_config_write_wpkt_quanta(vty, bgp);
		/* read quanta */
		bgp_config_write_rpkt_quanta(vty, bgp);

		/* coalesce time */
		bgp_config_write_coalesce_time(vty, bgp);

		/* BGP per-instance graceful-shutdown */
		/* BGP-wide settings and per-instance settings are mutually
		 * exclusive.
		 */
		if (!CHECK_FLAG(bm->flags, BM_FLAG_GRACEFUL_SHUTDOWN))
			if (CHECK_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_SHUTDOWN))
				vty_out(vty, " bgp graceful-shutdown\n");

		/* Long-lived Graceful Restart */
		if (bgp->llgr_stale_time != BGP_DEFAULT_LLGR_STALE_TIME)
			vty_out(vty,
				" bgp long-lived-graceful-restart stale-time %u\n",
				bgp->llgr_stale_time);

		/* BGP per-instance graceful-restart. */
		/* BGP-wide settings and per-instance settings are mutually
		 * exclusive.
		 */
		if (bm->stalepath_time == BGP_DEFAULT_STALEPATH_TIME)
			if (bgp->stalepath_time != BGP_DEFAULT_STALEPATH_TIME)
				vty_out(vty,
					" bgp graceful-restart stalepath-time %u\n",
					bgp->stalepath_time);

		if (bm->restart_time == BGP_DEFAULT_RESTART_TIME)
			if (bgp->restart_time != BGP_DEFAULT_RESTART_TIME)
				vty_out(vty,
					" bgp graceful-restart restart-time %u\n",
					bgp->restart_time);

		if (!!CHECK_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_NOTIFICATION) !=
		    SAVE_BGP_GRACEFUL_NOTIFICATION)
			vty_out(vty, " %sbgp graceful-restart notification\n",
				CHECK_FLAG(bgp->flags,
					   BGP_FLAG_GRACEFUL_NOTIFICATION)
					? ""
					: "no ");

		if (bm->select_defer_time == BGP_DEFAULT_SELECT_DEFERRAL_TIME)
			if (bgp->select_defer_time !=
			    BGP_DEFAULT_SELECT_DEFERRAL_TIME)
				vty_out(vty,
					" bgp graceful-restart select-defer-time %u\n",
					bgp->select_defer_time);

		if (!CHECK_FLAG(bm->flags, BM_FLAG_GR_CONFIGURED)) {
			if (bgp_global_gr_mode_get(bgp) == GLOBAL_GR)
				vty_out(vty, " bgp graceful-restart\n");

			if (bgp_global_gr_mode_get(bgp) == GLOBAL_DISABLE)
				vty_out(vty, " bgp graceful-restart-disable\n");
		}

		if (!CHECK_FLAG(bm->flags, BM_FLAG_GR_PRESERVE_FWD))
			if (CHECK_FLAG(bgp->flags, BGP_FLAG_GR_PRESERVE_FWD))
				vty_out(vty,
					" bgp graceful-restart preserve-fw-state\n");

		/* BGP TCP keepalive */
		bgp_config_tcp_keepalive(vty, bgp);

		if (bm->rib_stale_time == BGP_DEFAULT_RIB_STALE_TIME)
			if (bgp->rib_stale_time != BGP_DEFAULT_RIB_STALE_TIME)
				vty_out(vty,
					" bgp graceful-restart rib-stale-time %u\n",
					bgp->rib_stale_time);

		/* BGP bestpath method. */
		if (CHECK_FLAG(bgp->flags, BGP_FLAG_ASPATH_IGNORE))
			vty_out(vty, " bgp bestpath as-path ignore\n");
		if (CHECK_FLAG(bgp->flags, BGP_FLAG_ASPATH_CONFED))
			vty_out(vty, " bgp bestpath as-path confed\n");

		if (CHECK_FLAG(bgp->flags, BGP_FLAG_ASPATH_MULTIPATH_RELAX)) {
			if (CHECK_FLAG(bgp->flags,
				       BGP_FLAG_MULTIPATH_RELAX_AS_SET)) {
				vty_out(vty,
					" bgp bestpath as-path multipath-relax as-set\n");
			} else {
				vty_out(vty,
					" bgp bestpath as-path multipath-relax\n");
			}
		}

		if (CHECK_FLAG(bgp->flags, BGP_FLAG_RR_ALLOW_OUTBOUND_POLICY)) {
			vty_out(vty,
				" bgp route-reflector allow-outbound-policy\n");
		}
		if (CHECK_FLAG(bgp->flags, BGP_FLAG_COMPARE_ROUTER_ID))
			vty_out(vty, " bgp bestpath compare-routerid\n");
		if (CHECK_FLAG(bgp->flags, BGP_FLAG_COMPARE_AIGP))
			vty_out(vty, " bgp bestpath aigp\n");
		if (CHECK_FLAG(bgp->flags, BGP_FLAG_MED_CONFED)
		    || CHECK_FLAG(bgp->flags, BGP_FLAG_MED_MISSING_AS_WORST)) {
			vty_out(vty, " bgp bestpath med");
			if (CHECK_FLAG(bgp->flags, BGP_FLAG_MED_CONFED))
				vty_out(vty, " confed");
			if (CHECK_FLAG(bgp->flags,
				       BGP_FLAG_MED_MISSING_AS_WORST))
				vty_out(vty, " missing-as-worst");
			vty_out(vty, "\n");
		}

		if (CHECK_FLAG(bgp->flags, BGP_FLAG_PEERTYPE_MULTIPATH_RELAX))
			vty_out(vty,
				" bgp bestpath peer-type multipath-relax\n");

		/* Link bandwidth handling. */
		if (bgp->lb_handling == BGP_LINK_BW_IGNORE_BW)
			vty_out(vty, " bgp bestpath bandwidth ignore\n");
		else if (bgp->lb_handling == BGP_LINK_BW_SKIP_MISSING)
			vty_out(vty, " bgp bestpath bandwidth skip-missing\n");
		else if (bgp->lb_handling == BGP_LINK_BW_DEFWT_4_MISSING)
			vty_out(vty, " bgp bestpath bandwidth default-weight-for-missing\n");

		/* BGP network import check. */
		if (!!CHECK_FLAG(bgp->flags, BGP_FLAG_IMPORT_CHECK)
		    != SAVE_BGP_IMPORT_CHECK)
			vty_out(vty, " %sbgp network import-check\n",
				CHECK_FLAG(bgp->flags, BGP_FLAG_IMPORT_CHECK)
					? ""
					: "no ");

		/* BGP timers configuration. */
		if (bgp->default_keepalive != SAVE_BGP_KEEPALIVE
		    || bgp->default_holdtime != SAVE_BGP_HOLDTIME)
			vty_out(vty, " timers bgp %u %u\n",
				bgp->default_keepalive, bgp->default_holdtime);

		/* BGP minimum holdtime configuration. */
		if (bgp->default_min_holdtime != SAVE_BGP_HOLDTIME
		    && bgp->default_min_holdtime != 0)
			vty_out(vty, " bgp minimum-holdtime %u\n",
				bgp->default_min_holdtime);

		/* Conditional advertisement timer configuration */
		if (bgp->condition_check_period
		    != DEFAULT_CONDITIONAL_ROUTES_POLL_TIME)
			vty_out(vty,
				" bgp conditional-advertisement timer %u\n",
				bgp->condition_check_period);

		/* default-originate timer configuration */
		if (bgp->rmap_def_originate_eval_timer &&
		    bgp->rmap_def_originate_eval_timer !=
			    RMAP_DEFAULT_ORIGINATE_EVAL_TIMER)
			vty_out(vty, " bgp default-originate timer %u\n",
				bgp->rmap_def_originate_eval_timer);

		/* peer-group */
		for (ALL_LIST_ELEMENTS(bgp->group, node, nnode, group)) {
			bgp_config_write_peer_global(vty, bgp, group->conf);
		}

		/* Normal neighbor configuration. */
		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
			if (CHECK_FLAG(peer->flags, PEER_FLAG_CONFIG_NODE))
				bgp_config_write_peer_global(vty, bgp, peer);
		}

		/* listen range and limit for dynamic BGP neighbors */
		bgp_config_write_listen(vty, bgp);

		/*
		 * BGP default autoshutdown neighbors
		 *
		 * This must be placed after any peer and peer-group
		 * configuration, to avoid setting all peers to shutdown after
		 * a daemon restart, which is undesired behavior. (see #2286)
		 */
		if (bgp->autoshutdown)
			vty_out(vty, " bgp default shutdown\n");

		/* BGP instance administrative shutdown */
		if (CHECK_FLAG(bgp->flags, BGP_FLAG_SHUTDOWN))
			vty_out(vty, " bgp shutdown\n");

		/* Automatic RA enabling by BGP */
		if (!CHECK_FLAG(bm->flags, BM_FLAG_IPV6_NO_AUTO_RA))
			if (CHECK_FLAG(bgp->flags, BGP_FLAG_IPV6_NO_AUTO_RA))
				vty_out(vty, " no bgp ipv6-auto-ra\n");

		if (bgp->allow_martian)
			vty_out(vty, " bgp allow-martian-nexthop\n");

		if (bgp->fast_convergence)
			vty_out(vty, " bgp fast-convergence\n");

		if (bgp->srv6_enabled) {
			vty_frame(vty, " !\n segment-routing srv6\n");
			if (strlen(bgp->srv6_locator_name))
				vty_out(vty, "  locator %s\n",
					bgp->srv6_locator_name);
			vty_endframe(vty, " exit\n");
		}

		tovpn_sid_index = bgp->tovpn_sid_index;
		if (CHECK_FLAG(bgp->vrf_flags, BGP_VRF_TOVPN_SID_AUTO)) {
			vty_out(vty, " sid vpn per-vrf export auto\n");
		} else if (tovpn_sid_index != 0) {
			vty_out(vty, " sid vpn per-vrf export %d\n",
				tovpn_sid_index);
		}

		/* IPv4 unicast configuration.  */
		bgp_config_write_family(vty, bgp, AFI_IP, SAFI_UNICAST);

		/* IPv4 multicast configuration.  */
		bgp_config_write_family(vty, bgp, AFI_IP, SAFI_MULTICAST);

		/* IPv4 labeled-unicast configuration.  */
		bgp_config_write_family(vty, bgp, AFI_IP, SAFI_LABELED_UNICAST);

		/* IPv4 VPN configuration.  */
		bgp_config_write_family(vty, bgp, AFI_IP, SAFI_MPLS_VPN);

		/* ENCAPv4 configuration.  */
		bgp_config_write_family(vty, bgp, AFI_IP, SAFI_ENCAP);

		/* FLOWSPEC v4 configuration.  */
		bgp_config_write_family(vty, bgp, AFI_IP, SAFI_FLOWSPEC);

		/* IPv6 unicast configuration.  */
		bgp_config_write_family(vty, bgp, AFI_IP6, SAFI_UNICAST);

		/* IPv6 multicast configuration.  */
		bgp_config_write_family(vty, bgp, AFI_IP6, SAFI_MULTICAST);

		/* IPv6 labeled-unicast configuration.  */
		bgp_config_write_family(vty, bgp, AFI_IP6,
					SAFI_LABELED_UNICAST);

		/* IPv6 VPN configuration.  */
		bgp_config_write_family(vty, bgp, AFI_IP6, SAFI_MPLS_VPN);

		/* ENCAPv6 configuration.  */
		bgp_config_write_family(vty, bgp, AFI_IP6, SAFI_ENCAP);

		/* FLOWSPEC v6 configuration.  */
		bgp_config_write_family(vty, bgp, AFI_IP6, SAFI_FLOWSPEC);

		/* EVPN configuration.  */
		bgp_config_write_family(vty, bgp, AFI_L2VPN, SAFI_EVPN);

		hook_call(bgp_inst_config_write, bgp, vty);

#ifdef ENABLE_BGP_VNC
		bgp_rfapi_cfg_write(vty, bgp);
#endif

		vty_out(vty, "exit\n");
		vty_out(vty, "!\n");
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

static struct cmd_node bgp_srv6_node = {
	.name = "bgp srv6",
	.node = BGP_SRV6_NODE,
	.parent_node = BGP_NODE,
	.prompt = "%s(config-router-srv6)# ",
};

static void community_list_vty(void);

static void bgp_ac_peergroup(vector comps, struct cmd_token *token)
{
	struct bgp *bgp;
	struct peer_group *group;
	struct listnode *lnbgp, *lnpeer;

	for (ALL_LIST_ELEMENTS_RO(bm->bgp, lnbgp, bgp)) {
		for (ALL_LIST_ELEMENTS_RO(bgp->group, lnpeer, group))
			vector_set(comps,
				   XSTRDUP(MTYPE_COMPLETION, group->name));
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
			 * they'll otherwise show up multiple times */
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
	zlog_err("BGP configuration end timer expired after %d seconds.",
		 BGP_PRE_CONFIG_MAX_WAIT_SECONDS);
	bgp_config_finish(t);
}

static void bgp_config_start(void)
{
	EVENT_OFF(t_bgp_cfg);
	event_add_timer(bm->master, bgp_config_end_timeout, NULL,
			BGP_PRE_CONFIG_MAX_WAIT_SECONDS, &t_bgp_cfg);
}

/* When we receive a hook the configuration is read,
 * we start a timer to make sure we postpone sending
 * EoR before route-maps are processed.
 * This is especially valid if using `bgp route-map delay-timer`.
 */
static void bgp_config_end(void)
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

	EVENT_OFF(t_bgp_cfg);

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

DEFPY(mpls_bgp_forwarding, mpls_bgp_forwarding_cmd,
      "[no$no] mpls bgp forwarding",
      NO_STR MPLS_STR BGP_STR
      "Enable MPLS forwarding for eBGP directly connected peers\n")
{
	bool check;
	struct bgp_interface *iifp;

	VTY_DECLVAR_CONTEXT(interface, ifp);
	iifp = ifp->info;
	if (!iifp) {
		vty_out(vty, "Interface %s not available\n", ifp->name);
		return CMD_WARNING_CONFIG_FAILED;
	}
	check = CHECK_FLAG(iifp->flags, BGP_INTERFACE_MPLS_BGP_FORWARDING);
	if (check != !no) {
		if (no)
			UNSET_FLAG(iifp->flags,
				   BGP_INTERFACE_MPLS_BGP_FORWARDING);
		else
			SET_FLAG(iifp->flags,
				 BGP_INTERFACE_MPLS_BGP_FORWARDING);
		/* trigger a nht update on eBGP sessions */
		if (if_is_operative(ifp))
			bgp_nht_ifp_up(ifp);
	}
	return CMD_SUCCESS;
}

DEFPY(mpls_bgp_l3vpn_multi_domain_switching,
      mpls_bgp_l3vpn_multi_domain_switching_cmd,
      "[no$no] mpls bgp l3vpn-multi-domain-switching",
      NO_STR MPLS_STR BGP_STR
      "Bind a local MPLS label to incoming L3VPN updates\n")
{
	bool check;
	struct bgp_interface *iifp;

	VTY_DECLVAR_CONTEXT(interface, ifp);
	iifp = ifp->info;
	if (!iifp) {
		vty_out(vty, "Interface %s not available\n", ifp->name);
		return CMD_WARNING_CONFIG_FAILED;
	}
	check = CHECK_FLAG(iifp->flags, BGP_INTERFACE_MPLS_L3VPN_SWITCHING);
	if (check == !no)
		return CMD_SUCCESS;
	if (no)
		UNSET_FLAG(iifp->flags, BGP_INTERFACE_MPLS_L3VPN_SWITCHING);
	else
		SET_FLAG(iifp->flags, BGP_INTERFACE_MPLS_L3VPN_SWITCHING);
	/* trigger a nht update on eBGP sessions */
	if (if_is_operative(ifp))
		bgp_nht_ifp_up(ifp);

	return CMD_SUCCESS;
}

DEFPY (bgp_inq_limit,
       bgp_inq_limit_cmd,
       "bgp input-queue-limit (1-4294967295)$limit",
       BGP_STR
       "Set the BGP Input Queue limit for all peers when message parsing\n"
       "Input-Queue limit\n")
{
	bm->inq_limit = limit;

	return CMD_SUCCESS;
}

DEFPY (no_bgp_inq_limit,
       no_bgp_inq_limit_cmd,
       "no bgp input-queue-limit [(1-4294967295)$limit]",
       NO_STR
       BGP_STR
       "Set the BGP Input Queue limit for all peers when message parsing\n"
       "Input-Queue limit\n")
{
	bm->inq_limit = BM_DEFAULT_Q_LIMIT;

	return CMD_SUCCESS;
}

DEFPY (bgp_outq_limit,
       bgp_outq_limit_cmd,
       "bgp output-queue-limit (1-4294967295)$limit",
       BGP_STR
       "Set the BGP Output Queue limit for all peers when message parsing\n"
       "Output-Queue limit\n")
{
	bm->outq_limit = limit;

	return CMD_SUCCESS;
}

DEFPY (no_bgp_outq_limit,
       no_bgp_outq_limit_cmd,
       "no bgp output-queue-limit [(1-4294967295)$limit]",
       NO_STR
       BGP_STR
       "Set the BGP Output Queue limit for all peers when message parsing\n"
       "Output-Queue limit\n")
{
	bm->outq_limit = BM_DEFAULT_Q_LIMIT;

	return CMD_SUCCESS;
}


/* Initialization of BGP interface. */
static void bgp_vty_if_init(void)
{
	/* Install interface node. */
	if_cmd_init(config_write_interface);

	/* "mpls bgp forwarding" commands. */
	install_element(INTERFACE_NODE, &mpls_bgp_forwarding_cmd);
	install_element(INTERFACE_NODE,
			&mpls_bgp_l3vpn_multi_domain_switching_cmd);
}

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
	install_node(&bgp_srv6_node);

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
	install_default(BGP_EVPN_NODE);
	install_default(BGP_EVPN_VNI_NODE);
	install_default(BGP_SRV6_NODE);

	/* "global bgp inq-limit command */
	install_element(CONFIG_NODE, &bgp_inq_limit_cmd);
	install_element(CONFIG_NODE, &no_bgp_inq_limit_cmd);
	install_element(CONFIG_NODE, &bgp_outq_limit_cmd);
	install_element(CONFIG_NODE, &no_bgp_outq_limit_cmd);

	/* "bgp local-mac" hidden commands. */
	install_element(CONFIG_NODE, &bgp_local_mac_cmd);
	install_element(CONFIG_NODE, &no_bgp_local_mac_cmd);

	/* "bgp suppress-fib-pending" global */
	install_element(CONFIG_NODE, &bgp_global_suppress_fib_pending_cmd);

	/* bgp route-map delay-timer commands. */
	install_element(CONFIG_NODE, &bgp_set_route_map_delay_timer_cmd);
	install_element(CONFIG_NODE, &no_bgp_set_route_map_delay_timer_cmd);

	install_element(BGP_NODE, &bgp_allow_martian_cmd);

	/* bgp fast-convergence command */
	install_element(BGP_NODE, &bgp_fast_convergence_cmd);
	install_element(BGP_NODE, &no_bgp_fast_convergence_cmd);

	/* global bgp ipv6-auto-ra command */
	install_element(CONFIG_NODE, &bgp_ipv6_auto_ra_cmd);

	/* bgp ipv6-auto-ra command */
	install_element(BGP_NODE, &bgp_ipv6_auto_ra_cmd);

	/* global bgp update-delay command */
	install_element(CONFIG_NODE, &bgp_global_update_delay_cmd);
	install_element(CONFIG_NODE, &no_bgp_global_update_delay_cmd);

	/* global bgp graceful-shutdown command */
	install_element(CONFIG_NODE, &bgp_graceful_shutdown_cmd);
	install_element(CONFIG_NODE, &no_bgp_graceful_shutdown_cmd);

	/* BGP-wide graceful-restart commands. */
	install_element(CONFIG_NODE, &bgp_graceful_restart_cmd);
	install_element(CONFIG_NODE, &no_bgp_graceful_restart_cmd);
	install_element(CONFIG_NODE, &bgp_graceful_restart_disable_cmd);
	install_element(CONFIG_NODE, &no_bgp_graceful_restart_disable_cmd);
	install_element(CONFIG_NODE, &bgp_graceful_restart_stalepath_time_cmd);
	install_element(CONFIG_NODE,
			&no_bgp_graceful_restart_stalepath_time_cmd);
	install_element(CONFIG_NODE, &bgp_graceful_restart_restart_time_cmd);
	install_element(CONFIG_NODE, &no_bgp_graceful_restart_restart_time_cmd);
	install_element(CONFIG_NODE,
			&bgp_graceful_restart_select_defer_time_cmd);
	install_element(CONFIG_NODE,
			&no_bgp_graceful_restart_select_defer_time_cmd);
	install_element(CONFIG_NODE, &bgp_graceful_restart_preserve_fw_cmd);
	install_element(CONFIG_NODE, &no_bgp_graceful_restart_preserve_fw_cmd);
	install_element(CONFIG_NODE, &bgp_graceful_restart_rib_stale_time_cmd);
	install_element(CONFIG_NODE,
			&no_bgp_graceful_restart_rib_stale_time_cmd);

	/* Dummy commands (Currently not supported) */
	install_element(BGP_NODE, &no_synchronization_cmd);
	install_element(BGP_NODE, &no_auto_summary_cmd);

	/* "router bgp" commands. */
	install_element(CONFIG_NODE, &router_bgp_cmd);

	/* "no router bgp" commands. */
	install_element(CONFIG_NODE, &no_router_bgp_cmd);

	/* "bgp session-dscp command */
	install_element(CONFIG_NODE, &bgp_session_dscp_cmd);
	install_element(CONFIG_NODE, &no_bgp_session_dscp_cmd);

	/* "bgp router-id" commands. */
	install_element(BGP_NODE, &bgp_router_id_cmd);
	install_element(BGP_NODE, &no_bgp_router_id_cmd);

	/* "bgp suppress-fib-pending" command */
	install_element(BGP_NODE, &bgp_suppress_fib_pending_cmd);

	/* "bgp cluster-id" commands. */
	install_element(BGP_NODE, &bgp_cluster_id_cmd);
	install_element(BGP_NODE, &no_bgp_cluster_id_cmd);

	/* "bgp no-rib" commands. */
	install_element(CONFIG_NODE, &bgp_norib_cmd);
	install_element(CONFIG_NODE, &no_bgp_norib_cmd);

	install_element(CONFIG_NODE, &no_bgp_send_extra_data_cmd);

	/* "bgp confederation" commands. */
	install_element(BGP_NODE, &bgp_confederation_identifier_cmd);
	install_element(BGP_NODE, &no_bgp_confederation_identifier_cmd);

	/* "bgp confederation peers" commands. */
	install_element(BGP_NODE, &bgp_confederation_peers_cmd);
	install_element(BGP_NODE, &no_bgp_confederation_peers_cmd);

	/* bgp max-med command */
	install_element(BGP_NODE, &bgp_maxmed_admin_cmd);
	install_element(BGP_NODE, &no_bgp_maxmed_admin_cmd);
	install_element(BGP_NODE, &bgp_maxmed_admin_medv_cmd);
	install_element(BGP_NODE, &bgp_maxmed_onstartup_cmd);
	install_element(BGP_NODE, &no_bgp_maxmed_onstartup_cmd);

	/* "neighbor role" commands. */
	install_element(BGP_NODE, &neighbor_role_cmd);
	install_element(BGP_NODE, &neighbor_role_strict_cmd);
	install_element(BGP_NODE, &no_neighbor_role_cmd);

	/* "neighbor oad" commands. */
	install_element(BGP_NODE, &neighbor_oad_cmd);

	/* "neighbor aigp" commands. */
	install_element(BGP_NODE, &neighbor_aigp_cmd);

	/* "neighbor graceful-shutdown" command */
	install_element(BGP_NODE, &neighbor_graceful_shutdown_cmd);

	/* bgp disable-ebgp-connected-nh-check */
	install_element(BGP_NODE, &bgp_disable_connected_route_check_cmd);
	install_element(BGP_NODE, &no_bgp_disable_connected_route_check_cmd);

	/* bgp update-delay command */
	install_element(BGP_NODE, &bgp_update_delay_cmd);
	install_element(BGP_NODE, &no_bgp_update_delay_cmd);

	install_element(BGP_NODE, &bgp_wpkt_quanta_cmd);
	install_element(BGP_NODE, &bgp_rpkt_quanta_cmd);

	install_element(BGP_NODE, &bgp_coalesce_time_cmd);
	install_element(BGP_NODE, &no_bgp_coalesce_time_cmd);

	/* "maximum-paths" commands. */
	install_element(BGP_NODE, &bgp_maxpaths_hidden_cmd);
	install_element(BGP_NODE, &no_bgp_maxpaths_hidden_cmd);
	install_element(BGP_IPV4_NODE, &bgp_maxpaths_cmd);
	install_element(BGP_IPV4_NODE, &no_bgp_maxpaths_cmd);
	install_element(BGP_IPV6_NODE, &bgp_maxpaths_cmd);
	install_element(BGP_IPV6_NODE, &no_bgp_maxpaths_cmd);
	install_element(BGP_NODE, &bgp_maxpaths_ibgp_hidden_cmd);
	install_element(BGP_NODE, &bgp_maxpaths_ibgp_cluster_hidden_cmd);
	install_element(BGP_NODE, &no_bgp_maxpaths_ibgp_hidden_cmd);
	install_element(BGP_IPV4_NODE, &bgp_maxpaths_ibgp_cmd);
	install_element(BGP_IPV4_NODE, &bgp_maxpaths_ibgp_cluster_cmd);
	install_element(BGP_IPV4_NODE, &no_bgp_maxpaths_ibgp_cmd);
	install_element(BGP_IPV6_NODE, &bgp_maxpaths_ibgp_cmd);
	install_element(BGP_IPV6_NODE, &bgp_maxpaths_ibgp_cluster_cmd);
	install_element(BGP_IPV6_NODE, &no_bgp_maxpaths_ibgp_cmd);

	install_element(BGP_IPV4L_NODE, &bgp_maxpaths_cmd);
	install_element(BGP_IPV4L_NODE, &no_bgp_maxpaths_cmd);
	install_element(BGP_IPV4L_NODE, &bgp_maxpaths_ibgp_cmd);
	install_element(BGP_IPV4L_NODE, &bgp_maxpaths_ibgp_cluster_cmd);
	install_element(BGP_IPV4L_NODE, &no_bgp_maxpaths_ibgp_cmd);
	install_element(BGP_IPV6L_NODE, &bgp_maxpaths_cmd);
	install_element(BGP_IPV6L_NODE, &no_bgp_maxpaths_cmd);
	install_element(BGP_IPV6L_NODE, &bgp_maxpaths_ibgp_cmd);
	install_element(BGP_IPV6L_NODE, &bgp_maxpaths_ibgp_cluster_cmd);
	install_element(BGP_IPV6L_NODE, &no_bgp_maxpaths_ibgp_cmd);

	/* "timers bgp" commands. */
	install_element(BGP_NODE, &bgp_timers_cmd);
	install_element(BGP_NODE, &no_bgp_timers_cmd);

	/* "minimum-holdtime" commands. */
	install_element(BGP_NODE, &bgp_minimum_holdtime_cmd);
	install_element(BGP_NODE, &no_bgp_minimum_holdtime_cmd);

	/* route-map delay-timer commands - per instance for backwards compat.
	 */
	install_element(BGP_NODE, &bgp_set_route_map_delay_timer_cmd);
	install_element(BGP_NODE, &no_bgp_set_route_map_delay_timer_cmd);

	/* "bgp client-to-client reflection" commands */
	install_element(BGP_NODE, &no_bgp_client_to_client_reflection_cmd);
	install_element(BGP_NODE, &bgp_client_to_client_reflection_cmd);

	/* "bgp always-compare-med" commands */
	install_element(BGP_NODE, &bgp_always_compare_med_cmd);
	install_element(BGP_NODE, &no_bgp_always_compare_med_cmd);

	/* bgp ebgp-requires-policy */
	install_element(BGP_NODE, &bgp_ebgp_requires_policy_cmd);
	install_element(BGP_NODE, &no_bgp_ebgp_requires_policy_cmd);

	/* bgp enforce-first-as */
	install_element(BGP_NODE, &bgp_enforce_first_as_cmd);

	/* bgp labeled-unicast explicit-null */
	install_element(BGP_NODE, &bgp_lu_uses_explicit_null_cmd);

	/* bgp suppress-duplicates */
	install_element(BGP_NODE, &bgp_suppress_duplicates_cmd);
	install_element(BGP_NODE, &no_bgp_suppress_duplicates_cmd);

	/* bgp reject-as-sets */
	install_element(BGP_NODE, &bgp_reject_as_sets_cmd);
	install_element(BGP_NODE, &no_bgp_reject_as_sets_cmd);

	/* "bgp deterministic-med" commands */
	install_element(BGP_NODE, &bgp_deterministic_med_cmd);
	install_element(BGP_NODE, &no_bgp_deterministic_med_cmd);

	/* "bgp graceful-restart" command */
	install_element(BGP_NODE, &bgp_graceful_restart_cmd);
	install_element(BGP_NODE, &no_bgp_graceful_restart_cmd);

	/* "bgp graceful-restart-disable" command */
	install_element(BGP_NODE, &bgp_graceful_restart_disable_cmd);
	install_element(BGP_NODE, &no_bgp_graceful_restart_disable_cmd);

	/* "neighbor a:b:c:d graceful-restart" command */
	install_element(BGP_NODE, &bgp_neighbor_graceful_restart_set_cmd);
	install_element(BGP_NODE, &no_bgp_neighbor_graceful_restart_set_cmd);

	/* "neighbor a:b:c:d graceful-restart-disable" command */
	install_element(BGP_NODE,
			&bgp_neighbor_graceful_restart_disable_set_cmd);
	install_element(BGP_NODE,
			&no_bgp_neighbor_graceful_restart_disable_set_cmd);

	/* "neighbor a:b:c:d graceful-restart-helper" command */
	install_element(BGP_NODE,
			&bgp_neighbor_graceful_restart_helper_set_cmd);
	install_element(BGP_NODE,
			&no_bgp_neighbor_graceful_restart_helper_set_cmd);

	install_element(BGP_NODE, &bgp_graceful_restart_stalepath_time_cmd);
	install_element(BGP_NODE, &no_bgp_graceful_restart_stalepath_time_cmd);
	install_element(BGP_NODE, &bgp_graceful_restart_restart_time_cmd);
	install_element(BGP_NODE, &no_bgp_graceful_restart_restart_time_cmd);
	install_element(BGP_NODE, &bgp_graceful_restart_select_defer_time_cmd);
	install_element(BGP_NODE,
			&no_bgp_graceful_restart_select_defer_time_cmd);
	install_element(BGP_NODE, &bgp_graceful_restart_preserve_fw_cmd);
	install_element(BGP_NODE, &no_bgp_graceful_restart_preserve_fw_cmd);
	install_element(BGP_NODE, &bgp_graceful_restart_notification_cmd);

	install_element(BGP_NODE, &bgp_graceful_restart_disable_eor_cmd);
	install_element(BGP_NODE, &no_bgp_graceful_restart_disable_eor_cmd);
	install_element(BGP_NODE, &bgp_graceful_restart_rib_stale_time_cmd);
	install_element(BGP_NODE, &no_bgp_graceful_restart_rib_stale_time_cmd);

	/* "bgp graceful-shutdown" commands */
	install_element(BGP_NODE, &bgp_graceful_shutdown_cmd);
	install_element(BGP_NODE, &no_bgp_graceful_shutdown_cmd);

	/* "bgp hard-administrative-reset" commands */
	install_element(BGP_NODE, &bgp_administrative_reset_cmd);

	/* "bgp long-lived-graceful-restart" commands */
	install_element(BGP_NODE, &bgp_llgr_stalepath_time_cmd);
	install_element(BGP_NODE, &no_bgp_llgr_stalepath_time_cmd);

	/* "bgp fast-external-failover" commands */
	install_element(BGP_NODE, &bgp_fast_external_failover_cmd);
	install_element(BGP_NODE, &no_bgp_fast_external_failover_cmd);

	/* "bgp bestpath aigp" commands */
	install_element(BGP_NODE, &bgp_bestpath_aigp_cmd);

	/* "bgp bestpath compare-routerid" commands */
	install_element(BGP_NODE, &bgp_bestpath_compare_router_id_cmd);
	install_element(BGP_NODE, &no_bgp_bestpath_compare_router_id_cmd);

	/* "bgp bestpath as-path ignore" commands */
	install_element(BGP_NODE, &bgp_bestpath_aspath_ignore_cmd);
	install_element(BGP_NODE, &no_bgp_bestpath_aspath_ignore_cmd);

	/* "bgp bestpath as-path confed" commands */
	install_element(BGP_NODE, &bgp_bestpath_aspath_confed_cmd);
	install_element(BGP_NODE, &no_bgp_bestpath_aspath_confed_cmd);

	/* "bgp bestpath as-path multipath-relax" commands */
	install_element(BGP_NODE, &bgp_bestpath_aspath_multipath_relax_cmd);
	install_element(BGP_NODE, &no_bgp_bestpath_aspath_multipath_relax_cmd);

	/* "bgp bestpath peer-type multipath-relax" commands */
	install_element(BGP_NODE, &bgp_bestpath_peer_type_multipath_relax_cmd);
	install_element(BGP_NODE,
			&no_bgp_bestpath_peer_type_multipath_relax_cmd);

	/* "bgp log-neighbor-changes" commands */
	install_element(BGP_NODE, &bgp_log_neighbor_changes_cmd);
	install_element(BGP_NODE, &no_bgp_log_neighbor_changes_cmd);

	/* "bgp bestpath med" commands */
	install_element(BGP_NODE, &bgp_bestpath_med_cmd);
	install_element(BGP_NODE, &no_bgp_bestpath_med_cmd);

	/* "bgp bestpath bandwidth" commands */
	install_element(BGP_NODE, &bgp_bestpath_bw_cmd);
	install_element(BGP_NODE, &no_bgp_bestpath_bw_cmd);

	/* "no bgp default <afi>-<safi>" commands. */
	install_element(BGP_NODE, &bgp_default_afi_safi_cmd);

	/* "bgp network import-check" commands. */
	install_element(BGP_NODE, &bgp_network_import_check_cmd);
	install_element(BGP_NODE, &no_bgp_network_import_check_cmd);

	/* "bgp default local-preference" commands. */
	install_element(BGP_NODE, &bgp_default_local_preference_cmd);
	install_element(BGP_NODE, &no_bgp_default_local_preference_cmd);

	/* bgp default show-hostname */
	install_element(BGP_NODE, &bgp_default_show_hostname_cmd);
	install_element(BGP_NODE, &no_bgp_default_show_hostname_cmd);

	/* bgp default show-nexthop-hostname */
	install_element(BGP_NODE, &bgp_default_show_nexthop_hostname_cmd);
	install_element(BGP_NODE, &no_bgp_default_show_nexthop_hostname_cmd);

	/* bgp default software-version-capability */
	install_element(BGP_NODE, &bgp_default_software_version_capability_cmd);

	/* bgp default dynamic-capability */
	install_element(BGP_NODE, &bgp_default_dynamic_capability_cmd);

	/* "bgp default subgroup-pkt-queue-max" commands. */
	install_element(BGP_NODE, &bgp_default_subgroup_pkt_queue_max_cmd);
	install_element(BGP_NODE, &no_bgp_default_subgroup_pkt_queue_max_cmd);

	/* bgp ibgp-allow-policy-mods command */
	install_element(BGP_NODE, &bgp_rr_allow_outbound_policy_cmd);
	install_element(BGP_NODE, &no_bgp_rr_allow_outbound_policy_cmd);

	/* "bgp listen limit" commands. */
	install_element(BGP_NODE, &bgp_listen_limit_cmd);
	install_element(BGP_NODE, &no_bgp_listen_limit_cmd);

	/* "bgp listen range" commands. */
	install_element(BGP_NODE, &bgp_listen_range_cmd);
	install_element(BGP_NODE, &no_bgp_listen_range_cmd);

	/* "bgp default shutdown" command */
	install_element(BGP_NODE, &bgp_default_shutdown_cmd);

	/* "bgp shutdown" commands */
	install_element(BGP_NODE, &bgp_shutdown_cmd);
	install_element(BGP_NODE, &bgp_shutdown_msg_cmd);
	install_element(BGP_NODE, &no_bgp_shutdown_cmd);
	install_element(BGP_NODE, &no_bgp_shutdown_msg_cmd);

	/* "neighbor remote-as" commands. */
	install_element(BGP_NODE, &neighbor_remote_as_cmd);
	install_element(BGP_NODE, &neighbor_interface_config_cmd);
	install_element(BGP_NODE, &neighbor_interface_config_v6only_cmd);
	install_element(BGP_NODE, &neighbor_interface_config_remote_as_cmd);
	install_element(BGP_NODE,
			&neighbor_interface_v6only_config_remote_as_cmd);
	install_element(BGP_NODE, &no_neighbor_cmd);
	install_element(BGP_NODE, &no_neighbor_interface_config_cmd);

	/* "neighbor peer-group" commands. */
	install_element(BGP_NODE, &neighbor_peer_group_cmd);
	install_element(BGP_NODE, &no_neighbor_peer_group_cmd);
	install_element(BGP_NODE,
			&no_neighbor_interface_peer_group_remote_as_cmd);

	/* "neighbor local-as" commands. */
	install_element(BGP_NODE, &neighbor_local_as_cmd);
	install_element(BGP_NODE, &neighbor_local_as_no_prepend_cmd);
	install_element(BGP_NODE, &neighbor_local_as_no_prepend_replace_as_cmd);
	install_element(BGP_NODE, &no_neighbor_local_as_cmd);

	/* "neighbor solo" commands. */
	install_element(BGP_NODE, &neighbor_solo_cmd);
	install_element(BGP_NODE, &no_neighbor_solo_cmd);

	/* "neighbor password" commands. */
	install_element(BGP_NODE, &neighbor_password_cmd);
	install_element(BGP_NODE, &no_neighbor_password_cmd);

	/* "neighbor activate" commands. */
	install_element(BGP_NODE, &neighbor_activate_hidden_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_activate_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_activate_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_activate_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_activate_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_activate_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_activate_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_activate_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_activate_cmd);
	install_element(BGP_FLOWSPECV4_NODE, &neighbor_activate_cmd);
	install_element(BGP_FLOWSPECV6_NODE, &neighbor_activate_cmd);
	install_element(BGP_EVPN_NODE, &neighbor_activate_cmd);

	/* "no neighbor activate" commands. */
	install_element(BGP_NODE, &no_neighbor_activate_hidden_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_activate_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_activate_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_activate_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_activate_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_activate_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_activate_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_activate_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_activate_cmd);
	install_element(BGP_FLOWSPECV4_NODE, &no_neighbor_activate_cmd);
	install_element(BGP_FLOWSPECV6_NODE, &no_neighbor_activate_cmd);
	install_element(BGP_EVPN_NODE, &no_neighbor_activate_cmd);

	/* "neighbor peer-group" set commands. */
	install_element(BGP_NODE, &neighbor_set_peer_group_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_set_peer_group_hidden_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_set_peer_group_hidden_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_set_peer_group_hidden_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_set_peer_group_hidden_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_set_peer_group_hidden_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_set_peer_group_hidden_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_set_peer_group_hidden_cmd);
	install_element(BGP_FLOWSPECV4_NODE,
			&neighbor_set_peer_group_hidden_cmd);
	install_element(BGP_FLOWSPECV6_NODE,
			&neighbor_set_peer_group_hidden_cmd);

	/* "no neighbor peer-group unset" commands. */
	install_element(BGP_NODE, &no_neighbor_set_peer_group_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_set_peer_group_hidden_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_set_peer_group_hidden_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_set_peer_group_hidden_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_set_peer_group_hidden_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_set_peer_group_hidden_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_set_peer_group_hidden_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_set_peer_group_hidden_cmd);
	install_element(BGP_FLOWSPECV4_NODE,
			&no_neighbor_set_peer_group_hidden_cmd);
	install_element(BGP_FLOWSPECV6_NODE,
			&no_neighbor_set_peer_group_hidden_cmd);

	/* "neighbor softreconfiguration inbound" commands.*/
	install_element(BGP_NODE, &neighbor_soft_reconfiguration_hidden_cmd);
	install_element(BGP_NODE, &no_neighbor_soft_reconfiguration_hidden_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_soft_reconfiguration_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_soft_reconfiguration_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_soft_reconfiguration_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_soft_reconfiguration_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_soft_reconfiguration_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_soft_reconfiguration_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_soft_reconfiguration_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_soft_reconfiguration_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_soft_reconfiguration_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_soft_reconfiguration_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_soft_reconfiguration_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_soft_reconfiguration_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_soft_reconfiguration_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_soft_reconfiguration_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_soft_reconfiguration_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_soft_reconfiguration_cmd);
	install_element(BGP_FLOWSPECV4_NODE,
			&neighbor_soft_reconfiguration_cmd);
	install_element(BGP_FLOWSPECV4_NODE,
			&no_neighbor_soft_reconfiguration_cmd);
	install_element(BGP_FLOWSPECV6_NODE,
			&neighbor_soft_reconfiguration_cmd);
	install_element(BGP_FLOWSPECV6_NODE,
			&no_neighbor_soft_reconfiguration_cmd);
	install_element(BGP_EVPN_NODE, &neighbor_soft_reconfiguration_cmd);
	install_element(BGP_EVPN_NODE, &no_neighbor_soft_reconfiguration_cmd);

	/* "neighbor attribute-unchanged" commands.  */
	install_element(BGP_NODE, &neighbor_attr_unchanged_hidden_cmd);
	install_element(BGP_NODE, &no_neighbor_attr_unchanged_hidden_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_attr_unchanged_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_attr_unchanged_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_attr_unchanged_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_attr_unchanged_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_attr_unchanged_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_attr_unchanged_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_attr_unchanged_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_attr_unchanged_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_attr_unchanged_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_attr_unchanged_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_attr_unchanged_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_attr_unchanged_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_attr_unchanged_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_attr_unchanged_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_attr_unchanged_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_attr_unchanged_cmd);

	install_element(BGP_EVPN_NODE, &neighbor_attr_unchanged_cmd);
	install_element(BGP_EVPN_NODE, &no_neighbor_attr_unchanged_cmd);

	install_element(BGP_FLOWSPECV4_NODE, &neighbor_attr_unchanged_cmd);
	install_element(BGP_FLOWSPECV4_NODE, &no_neighbor_attr_unchanged_cmd);
	install_element(BGP_FLOWSPECV6_NODE, &neighbor_attr_unchanged_cmd);
	install_element(BGP_FLOWSPECV6_NODE, &no_neighbor_attr_unchanged_cmd);

	/* "nexthop-local unchanged" commands */
	install_element(BGP_IPV6_NODE, &neighbor_nexthop_local_unchanged_cmd);
	install_element(BGP_IPV6_NODE,
			&no_neighbor_nexthop_local_unchanged_cmd);

	/* "neighbor next-hop-self" commands. */
	install_element(BGP_NODE, &neighbor_nexthop_self_hidden_cmd);
	install_element(BGP_NODE, &no_neighbor_nexthop_self_hidden_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_nexthop_self_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_nexthop_self_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_nexthop_self_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_nexthop_self_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_nexthop_self_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_nexthop_self_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_nexthop_self_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_nexthop_self_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_nexthop_self_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_nexthop_self_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_nexthop_self_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_nexthop_self_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_nexthop_self_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_nexthop_self_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_nexthop_self_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_nexthop_self_cmd);
	install_element(BGP_EVPN_NODE, &neighbor_nexthop_self_cmd);
	install_element(BGP_EVPN_NODE, &no_neighbor_nexthop_self_cmd);

	/* "neighbor next-hop-self force" commands. */
	install_element(BGP_NODE, &neighbor_nexthop_self_force_hidden_cmd);
	install_element(BGP_NODE, &no_neighbor_nexthop_self_force_hidden_cmd);
	install_element(BGP_NODE, &neighbor_nexthop_self_all_hidden_cmd);
	install_element(BGP_NODE, &no_neighbor_nexthop_self_all_hidden_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_nexthop_self_force_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_nexthop_self_force_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_nexthop_self_all_hidden_cmd);
	install_element(BGP_IPV4_NODE,
			&no_neighbor_nexthop_self_all_hidden_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_nexthop_self_force_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_nexthop_self_force_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_nexthop_self_all_hidden_cmd);
	install_element(BGP_IPV4M_NODE,
			&no_neighbor_nexthop_self_all_hidden_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_nexthop_self_force_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_nexthop_self_force_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_nexthop_self_all_hidden_cmd);
	install_element(BGP_IPV4L_NODE,
			&no_neighbor_nexthop_self_all_hidden_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_nexthop_self_force_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_nexthop_self_force_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_nexthop_self_all_hidden_cmd);
	install_element(BGP_IPV6_NODE,
			&no_neighbor_nexthop_self_all_hidden_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_nexthop_self_force_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_nexthop_self_force_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_nexthop_self_all_hidden_cmd);
	install_element(BGP_IPV6M_NODE,
			&no_neighbor_nexthop_self_all_hidden_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_nexthop_self_force_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_nexthop_self_force_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_nexthop_self_all_hidden_cmd);
	install_element(BGP_IPV6L_NODE,
			&no_neighbor_nexthop_self_all_hidden_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_nexthop_self_force_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_nexthop_self_force_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_nexthop_self_all_hidden_cmd);
	install_element(BGP_VPNV4_NODE,
			&no_neighbor_nexthop_self_all_hidden_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_nexthop_self_force_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_nexthop_self_force_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_nexthop_self_all_hidden_cmd);
	install_element(BGP_VPNV6_NODE,
			&no_neighbor_nexthop_self_all_hidden_cmd);
	install_element(BGP_EVPN_NODE, &neighbor_nexthop_self_force_cmd);
	install_element(BGP_EVPN_NODE, &no_neighbor_nexthop_self_force_cmd);

	/* "neighbor as-override" commands. */
	install_element(BGP_NODE, &neighbor_as_override_hidden_cmd);
	install_element(BGP_NODE, &no_neighbor_as_override_hidden_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_as_override_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_as_override_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_as_override_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_as_override_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_as_override_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_as_override_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_as_override_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_as_override_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_as_override_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_as_override_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_as_override_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_as_override_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_as_override_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_as_override_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_as_override_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_as_override_cmd);

	/* "neighbor remove-private-AS" commands. */
	install_element(BGP_NODE, &neighbor_remove_private_as_hidden_cmd);
	install_element(BGP_NODE, &no_neighbor_remove_private_as_hidden_cmd);
	install_element(BGP_NODE, &neighbor_remove_private_as_all_hidden_cmd);
	install_element(BGP_NODE,
			&no_neighbor_remove_private_as_all_hidden_cmd);
	install_element(BGP_NODE,
			&neighbor_remove_private_as_replace_as_hidden_cmd);
	install_element(BGP_NODE,
			&no_neighbor_remove_private_as_replace_as_hidden_cmd);
	install_element(BGP_NODE,
			&neighbor_remove_private_as_all_replace_as_hidden_cmd);
	install_element(
		BGP_NODE,
		&no_neighbor_remove_private_as_all_replace_as_hidden_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_remove_private_as_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_remove_private_as_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_remove_private_as_all_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_remove_private_as_all_cmd);
	install_element(BGP_IPV4_NODE,
			&neighbor_remove_private_as_replace_as_cmd);
	install_element(BGP_IPV4_NODE,
			&no_neighbor_remove_private_as_replace_as_cmd);
	install_element(BGP_IPV4_NODE,
			&neighbor_remove_private_as_all_replace_as_cmd);
	install_element(BGP_IPV4_NODE,
			&no_neighbor_remove_private_as_all_replace_as_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_remove_private_as_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_remove_private_as_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_remove_private_as_all_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_remove_private_as_all_cmd);
	install_element(BGP_IPV4M_NODE,
			&neighbor_remove_private_as_replace_as_cmd);
	install_element(BGP_IPV4M_NODE,
			&no_neighbor_remove_private_as_replace_as_cmd);
	install_element(BGP_IPV4M_NODE,
			&neighbor_remove_private_as_all_replace_as_cmd);
	install_element(BGP_IPV4M_NODE,
			&no_neighbor_remove_private_as_all_replace_as_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_remove_private_as_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_remove_private_as_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_remove_private_as_all_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_remove_private_as_all_cmd);
	install_element(BGP_IPV4L_NODE,
			&neighbor_remove_private_as_replace_as_cmd);
	install_element(BGP_IPV4L_NODE,
			&no_neighbor_remove_private_as_replace_as_cmd);
	install_element(BGP_IPV4L_NODE,
			&neighbor_remove_private_as_all_replace_as_cmd);
	install_element(BGP_IPV4L_NODE,
			&no_neighbor_remove_private_as_all_replace_as_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_remove_private_as_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_remove_private_as_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_remove_private_as_all_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_remove_private_as_all_cmd);
	install_element(BGP_IPV6_NODE,
			&neighbor_remove_private_as_replace_as_cmd);
	install_element(BGP_IPV6_NODE,
			&no_neighbor_remove_private_as_replace_as_cmd);
	install_element(BGP_IPV6_NODE,
			&neighbor_remove_private_as_all_replace_as_cmd);
	install_element(BGP_IPV6_NODE,
			&no_neighbor_remove_private_as_all_replace_as_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_remove_private_as_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_remove_private_as_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_remove_private_as_all_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_remove_private_as_all_cmd);
	install_element(BGP_IPV6M_NODE,
			&neighbor_remove_private_as_replace_as_cmd);
	install_element(BGP_IPV6M_NODE,
			&no_neighbor_remove_private_as_replace_as_cmd);
	install_element(BGP_IPV6M_NODE,
			&neighbor_remove_private_as_all_replace_as_cmd);
	install_element(BGP_IPV6M_NODE,
			&no_neighbor_remove_private_as_all_replace_as_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_remove_private_as_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_remove_private_as_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_remove_private_as_all_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_remove_private_as_all_cmd);
	install_element(BGP_IPV6L_NODE,
			&neighbor_remove_private_as_replace_as_cmd);
	install_element(BGP_IPV6L_NODE,
			&no_neighbor_remove_private_as_replace_as_cmd);
	install_element(BGP_IPV6L_NODE,
			&neighbor_remove_private_as_all_replace_as_cmd);
	install_element(BGP_IPV6L_NODE,
			&no_neighbor_remove_private_as_all_replace_as_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_remove_private_as_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_remove_private_as_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_remove_private_as_all_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_remove_private_as_all_cmd);
	install_element(BGP_VPNV4_NODE,
			&neighbor_remove_private_as_replace_as_cmd);
	install_element(BGP_VPNV4_NODE,
			&no_neighbor_remove_private_as_replace_as_cmd);
	install_element(BGP_VPNV4_NODE,
			&neighbor_remove_private_as_all_replace_as_cmd);
	install_element(BGP_VPNV4_NODE,
			&no_neighbor_remove_private_as_all_replace_as_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_remove_private_as_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_remove_private_as_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_remove_private_as_all_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_remove_private_as_all_cmd);
	install_element(BGP_VPNV6_NODE,
			&neighbor_remove_private_as_replace_as_cmd);
	install_element(BGP_VPNV6_NODE,
			&no_neighbor_remove_private_as_replace_as_cmd);
	install_element(BGP_VPNV6_NODE,
			&neighbor_remove_private_as_all_replace_as_cmd);
	install_element(BGP_VPNV6_NODE,
			&no_neighbor_remove_private_as_all_replace_as_cmd);

	/* "neighbor send-community" commands.*/
	install_element(BGP_NODE, &neighbor_send_community_hidden_cmd);
	install_element(BGP_NODE, &neighbor_send_community_type_hidden_cmd);
	install_element(BGP_NODE, &no_neighbor_send_community_hidden_cmd);
	install_element(BGP_NODE, &no_neighbor_send_community_type_hidden_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_send_community_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_send_community_type_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_send_community_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_send_community_type_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_send_community_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_send_community_type_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_send_community_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_send_community_type_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_send_community_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_send_community_type_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_send_community_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_send_community_type_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_send_community_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_send_community_type_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_send_community_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_send_community_type_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_send_community_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_send_community_type_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_send_community_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_send_community_type_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_send_community_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_send_community_type_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_send_community_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_send_community_type_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_send_community_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_send_community_type_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_send_community_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_send_community_type_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_send_community_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_send_community_type_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_send_community_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_send_community_type_cmd);
	install_element(BGP_NODE, &neighbor_ecommunity_rpki_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_ecommunity_rpki_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_ecommunity_rpki_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_ecommunity_rpki_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_ecommunity_rpki_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_ecommunity_rpki_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_ecommunity_rpki_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_ecommunity_rpki_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_ecommunity_rpki_cmd);

	/* "neighbor route-reflector" commands.*/
	install_element(BGP_NODE, &neighbor_route_reflector_client_hidden_cmd);
	install_element(BGP_NODE,
			&no_neighbor_route_reflector_client_hidden_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_route_reflector_client_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_route_reflector_client_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_route_reflector_client_cmd);
	install_element(BGP_IPV4M_NODE,
			&no_neighbor_route_reflector_client_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_route_reflector_client_cmd);
	install_element(BGP_IPV4L_NODE,
			&no_neighbor_route_reflector_client_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_route_reflector_client_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_route_reflector_client_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_route_reflector_client_cmd);
	install_element(BGP_IPV6M_NODE,
			&no_neighbor_route_reflector_client_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_route_reflector_client_cmd);
	install_element(BGP_IPV6L_NODE,
			&no_neighbor_route_reflector_client_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_route_reflector_client_cmd);
	install_element(BGP_VPNV4_NODE,
			&no_neighbor_route_reflector_client_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_route_reflector_client_cmd);
	install_element(BGP_VPNV6_NODE,
			&no_neighbor_route_reflector_client_cmd);
	install_element(BGP_FLOWSPECV4_NODE,
			&neighbor_route_reflector_client_cmd);
	install_element(BGP_FLOWSPECV4_NODE,
			&no_neighbor_route_reflector_client_cmd);
	install_element(BGP_FLOWSPECV6_NODE,
			&neighbor_route_reflector_client_cmd);
	install_element(BGP_FLOWSPECV6_NODE,
			&no_neighbor_route_reflector_client_cmd);
	install_element(BGP_EVPN_NODE, &neighbor_route_reflector_client_cmd);
	install_element(BGP_EVPN_NODE, &no_neighbor_route_reflector_client_cmd);

	/* "neighbor route-server" commands.*/
	install_element(BGP_NODE, &neighbor_route_server_client_hidden_cmd);
	install_element(BGP_NODE, &no_neighbor_route_server_client_hidden_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_route_server_client_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_route_server_client_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_route_server_client_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_route_server_client_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_route_server_client_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_route_server_client_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_route_server_client_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_route_server_client_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_route_server_client_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_route_server_client_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_route_server_client_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_route_server_client_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_route_server_client_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_route_server_client_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_route_server_client_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_route_server_client_cmd);
	install_element(BGP_EVPN_NODE, &neighbor_route_server_client_cmd);
	install_element(BGP_EVPN_NODE, &no_neighbor_route_server_client_cmd);
	install_element(BGP_FLOWSPECV4_NODE, &neighbor_route_server_client_cmd);
	install_element(BGP_FLOWSPECV4_NODE,
			&no_neighbor_route_server_client_cmd);
	install_element(BGP_FLOWSPECV6_NODE, &neighbor_route_server_client_cmd);
	install_element(BGP_FLOWSPECV6_NODE,
			&no_neighbor_route_server_client_cmd);

	/* "neighbor disable-addpath-rx" commands. */
	install_element(BGP_IPV4_NODE, &neighbor_disable_addpath_rx_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_disable_addpath_rx_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_disable_addpath_rx_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_disable_addpath_rx_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_disable_addpath_rx_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_disable_addpath_rx_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_disable_addpath_rx_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_disable_addpath_rx_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_disable_addpath_rx_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_disable_addpath_rx_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_disable_addpath_rx_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_disable_addpath_rx_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_disable_addpath_rx_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_disable_addpath_rx_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_disable_addpath_rx_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_disable_addpath_rx_cmd);

	/* "neighbor addpath-tx-all-paths" commands.*/
	install_element(BGP_NODE, &neighbor_addpath_tx_all_paths_hidden_cmd);
	install_element(BGP_NODE, &no_neighbor_addpath_tx_all_paths_hidden_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_addpath_tx_all_paths_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_addpath_tx_all_paths_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_addpath_tx_all_paths_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_addpath_tx_all_paths_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_addpath_tx_all_paths_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_addpath_tx_all_paths_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_addpath_tx_all_paths_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_addpath_tx_all_paths_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_addpath_tx_all_paths_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_addpath_tx_all_paths_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_addpath_tx_all_paths_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_addpath_tx_all_paths_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_addpath_tx_all_paths_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_addpath_tx_all_paths_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_addpath_tx_all_paths_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_addpath_tx_all_paths_cmd);

	/* "neighbor addpath-tx-best-selected" commands.*/
	install_element(BGP_IPV4_NODE,
			&neighbor_addpath_tx_best_selected_paths_cmd);
	install_element(BGP_IPV4_NODE,
			&no_neighbor_addpath_tx_best_selected_paths_cmd);
	install_element(BGP_IPV4M_NODE,
			&neighbor_addpath_tx_best_selected_paths_cmd);
	install_element(BGP_IPV4M_NODE,
			&no_neighbor_addpath_tx_best_selected_paths_cmd);
	install_element(BGP_IPV4L_NODE,
			&neighbor_addpath_tx_best_selected_paths_cmd);
	install_element(BGP_IPV4L_NODE,
			&no_neighbor_addpath_tx_best_selected_paths_cmd);
	install_element(BGP_IPV6_NODE,
			&neighbor_addpath_tx_best_selected_paths_cmd);
	install_element(BGP_IPV6_NODE,
			&no_neighbor_addpath_tx_best_selected_paths_cmd);
	install_element(BGP_IPV6M_NODE,
			&neighbor_addpath_tx_best_selected_paths_cmd);
	install_element(BGP_IPV6M_NODE,
			&no_neighbor_addpath_tx_best_selected_paths_cmd);
	install_element(BGP_IPV6L_NODE,
			&neighbor_addpath_tx_best_selected_paths_cmd);
	install_element(BGP_IPV6L_NODE,
			&no_neighbor_addpath_tx_best_selected_paths_cmd);
	install_element(BGP_VPNV4_NODE,
			&neighbor_addpath_tx_best_selected_paths_cmd);
	install_element(BGP_VPNV4_NODE,
			&no_neighbor_addpath_tx_best_selected_paths_cmd);
	install_element(BGP_VPNV6_NODE,
			&neighbor_addpath_tx_best_selected_paths_cmd);
	install_element(BGP_VPNV6_NODE,
			&no_neighbor_addpath_tx_best_selected_paths_cmd);

	/* "neighbor addpath-tx-bestpath-per-AS" commands.*/
	install_element(BGP_NODE,
			&neighbor_addpath_tx_bestpath_per_as_hidden_cmd);
	install_element(BGP_NODE,
			&no_neighbor_addpath_tx_bestpath_per_as_hidden_cmd);
	install_element(BGP_IPV4_NODE,
			&neighbor_addpath_tx_bestpath_per_as_cmd);
	install_element(BGP_IPV4_NODE,
			&no_neighbor_addpath_tx_bestpath_per_as_cmd);
	install_element(BGP_IPV4M_NODE,
			&neighbor_addpath_tx_bestpath_per_as_cmd);
	install_element(BGP_IPV4M_NODE,
			&no_neighbor_addpath_tx_bestpath_per_as_cmd);
	install_element(BGP_IPV4L_NODE,
			&neighbor_addpath_tx_bestpath_per_as_cmd);
	install_element(BGP_IPV4L_NODE,
			&no_neighbor_addpath_tx_bestpath_per_as_cmd);
	install_element(BGP_IPV6_NODE,
			&neighbor_addpath_tx_bestpath_per_as_cmd);
	install_element(BGP_IPV6_NODE,
			&no_neighbor_addpath_tx_bestpath_per_as_cmd);
	install_element(BGP_IPV6M_NODE,
			&neighbor_addpath_tx_bestpath_per_as_cmd);
	install_element(BGP_IPV6M_NODE,
			&no_neighbor_addpath_tx_bestpath_per_as_cmd);
	install_element(BGP_IPV6L_NODE,
			&neighbor_addpath_tx_bestpath_per_as_cmd);
	install_element(BGP_IPV6L_NODE,
			&no_neighbor_addpath_tx_bestpath_per_as_cmd);
	install_element(BGP_VPNV4_NODE,
			&neighbor_addpath_tx_bestpath_per_as_cmd);
	install_element(BGP_VPNV4_NODE,
			&no_neighbor_addpath_tx_bestpath_per_as_cmd);
	install_element(BGP_VPNV6_NODE,
			&neighbor_addpath_tx_bestpath_per_as_cmd);
	install_element(BGP_VPNV6_NODE,
			&no_neighbor_addpath_tx_bestpath_per_as_cmd);

	/* "neighbor addpath-rx-paths-limit" commands.*/
	install_element(BGP_NODE, &neighbor_addpath_paths_limit_cmd);
	install_element(BGP_NODE, &no_neighbor_addpath_paths_limit_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_addpath_paths_limit_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_addpath_paths_limit_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_addpath_paths_limit_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_addpath_paths_limit_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_addpath_paths_limit_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_addpath_paths_limit_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_addpath_paths_limit_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_addpath_paths_limit_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_addpath_paths_limit_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_addpath_paths_limit_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_addpath_paths_limit_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_addpath_paths_limit_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_addpath_paths_limit_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_addpath_paths_limit_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_addpath_paths_limit_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_addpath_paths_limit_cmd);

	/* "neighbor sender-as-path-loop-detection" commands. */
	install_element(BGP_NODE, &neighbor_aspath_loop_detection_cmd);
	install_element(BGP_NODE, &no_neighbor_aspath_loop_detection_cmd);

	/* "neighbor path-attribute discard" commands. */
	install_element(BGP_NODE, &neighbor_path_attribute_discard_cmd);
	install_element(BGP_NODE, &no_neighbor_path_attribute_discard_cmd);

	/* "neighbor path-attribute treat-as-withdraw" commands. */
	install_element(BGP_NODE,
			&neighbor_path_attribute_treat_as_withdraw_cmd);
	install_element(BGP_NODE,
			&no_neighbor_path_attribute_treat_as_withdraw_cmd);

	/* "neighbor passive" commands. */
	install_element(BGP_NODE, &neighbor_passive_cmd);
	install_element(BGP_NODE, &no_neighbor_passive_cmd);


	/* "neighbor shutdown" commands. */
	install_element(BGP_NODE, &neighbor_shutdown_cmd);
	install_element(BGP_NODE, &no_neighbor_shutdown_cmd);
	install_element(BGP_NODE, &neighbor_shutdown_msg_cmd);
	install_element(BGP_NODE, &no_neighbor_shutdown_msg_cmd);
	install_element(BGP_NODE, &neighbor_shutdown_rtt_cmd);
	install_element(BGP_NODE, &no_neighbor_shutdown_rtt_cmd);

	/* "neighbor capability extended-nexthop" commands.*/
	install_element(BGP_NODE, &neighbor_capability_enhe_cmd);
	install_element(BGP_NODE, &no_neighbor_capability_enhe_cmd);

	/* "neighbor capability software-version" commands.*/
	install_element(BGP_NODE, &neighbor_capability_software_version_cmd);

	/* "neighbor capability orf prefix-list" commands.*/
	install_element(BGP_NODE, &neighbor_capability_orf_prefix_hidden_cmd);
	install_element(BGP_NODE,
			&no_neighbor_capability_orf_prefix_hidden_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_capability_orf_prefix_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_capability_orf_prefix_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_capability_orf_prefix_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_capability_orf_prefix_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_capability_orf_prefix_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_capability_orf_prefix_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_capability_orf_prefix_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_capability_orf_prefix_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_capability_orf_prefix_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_capability_orf_prefix_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_capability_orf_prefix_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_capability_orf_prefix_cmd);

	/* "neighbor capability dynamic" commands.*/
	install_element(BGP_NODE, &neighbor_capability_dynamic_cmd);
	install_element(BGP_NODE, &no_neighbor_capability_dynamic_cmd);

	/* "neighbor dont-capability-negotiate" commands. */
	install_element(BGP_NODE, &neighbor_dont_capability_negotiate_cmd);
	install_element(BGP_NODE, &no_neighbor_dont_capability_negotiate_cmd);

	/* "neighbor capability fqdn" command. */
	install_element(BGP_NODE, &neighbor_capability_fqdn_cmd);

	/* "neighbor ebgp-multihop" commands. */
	install_element(BGP_NODE, &neighbor_ebgp_multihop_cmd);
	install_element(BGP_NODE, &neighbor_ebgp_multihop_ttl_cmd);
	install_element(BGP_NODE, &no_neighbor_ebgp_multihop_cmd);

	/* "neighbor disable-connected-check" commands.  */
	install_element(BGP_NODE, &neighbor_disable_connected_check_cmd);
	install_element(BGP_NODE, &no_neighbor_disable_connected_check_cmd);

	/* "neighbor disable-link-bw-encoding-ieee" commands.  */
	install_element(BGP_NODE, &neighbor_disable_link_bw_encoding_ieee_cmd);
	install_element(BGP_NODE,
			&no_neighbor_disable_link_bw_encoding_ieee_cmd);


	install_element(BGP_NODE, &neighbor_extended_link_bw_cmd);

	/* "neighbor extended-optional-parameters" commands.  */
	install_element(BGP_NODE, &neighbor_extended_optional_parameters_cmd);
	install_element(BGP_NODE,
			&no_neighbor_extended_optional_parameters_cmd);

	/* "neighbor enforce-first-as" commands. */
	install_element(BGP_NODE, &neighbor_enforce_first_as_cmd);
	install_element(BGP_NODE, &no_neighbor_enforce_first_as_cmd);

	/* "neighbor description" commands. */
	install_element(BGP_NODE, &neighbor_description_cmd);
	install_element(BGP_NODE, &no_neighbor_description_cmd);
	install_element(BGP_NODE, &no_neighbor_description_comment_cmd);

	/* "neighbor update-source" commands. "*/
	install_element(BGP_NODE, &neighbor_update_source_cmd);
	install_element(BGP_NODE, &no_neighbor_update_source_cmd);

	/* "neighbor default-originate" commands. */
	install_element(BGP_NODE, &neighbor_default_originate_hidden_cmd);
	install_element(BGP_NODE, &neighbor_default_originate_rmap_hidden_cmd);
	install_element(BGP_NODE, &no_neighbor_default_originate_hidden_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_default_originate_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_default_originate_rmap_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_default_originate_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_default_originate_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_default_originate_rmap_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_default_originate_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_default_originate_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_default_originate_rmap_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_default_originate_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_default_originate_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_default_originate_rmap_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_default_originate_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_default_originate_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_default_originate_rmap_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_default_originate_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_default_originate_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_default_originate_rmap_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_default_originate_cmd);

	/* "neighbor port" commands. */
	install_element(BGP_NODE, &neighbor_port_cmd);
	install_element(BGP_NODE, &no_neighbor_port_cmd);

	/* "neighbor weight" commands. */
	install_element(BGP_NODE, &neighbor_weight_hidden_cmd);
	install_element(BGP_NODE, &no_neighbor_weight_hidden_cmd);

	install_element(BGP_IPV4_NODE, &neighbor_weight_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_weight_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_weight_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_weight_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_weight_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_weight_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_weight_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_weight_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_weight_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_weight_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_weight_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_weight_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_weight_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_weight_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_weight_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_weight_cmd);

	/* "neighbor override-capability" commands. */
	install_element(BGP_NODE, &neighbor_override_capability_cmd);
	install_element(BGP_NODE, &no_neighbor_override_capability_cmd);

	/* "neighbor strict-capability-match" commands. */
	install_element(BGP_NODE, &neighbor_strict_capability_cmd);
	install_element(BGP_NODE, &no_neighbor_strict_capability_cmd);

	/* "neighbor timers" commands. */
	install_element(BGP_NODE, &neighbor_timers_cmd);
	install_element(BGP_NODE, &no_neighbor_timers_cmd);

	/* "neighbor timers connect" commands. */
	install_element(BGP_NODE, &neighbor_timers_connect_cmd);
	install_element(BGP_NODE, &no_neighbor_timers_connect_cmd);

	/* "neighbor timers delayopen" commands. */
	install_element(BGP_NODE, &neighbor_timers_delayopen_cmd);
	install_element(BGP_NODE, &no_neighbor_timers_delayopen_cmd);

	/* "neighbor advertisement-interval" commands. */
	install_element(BGP_NODE, &neighbor_advertise_interval_cmd);
	install_element(BGP_NODE, &no_neighbor_advertise_interval_cmd);

	/* "neighbor interface" commands. */
	install_element(BGP_NODE, &neighbor_interface_cmd);
	install_element(BGP_NODE, &no_neighbor_interface_cmd);

	/* "neighbor distribute" commands. */
	install_element(BGP_NODE, &neighbor_distribute_list_hidden_cmd);
	install_element(BGP_NODE, &no_neighbor_distribute_list_hidden_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_distribute_list_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_distribute_list_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_distribute_list_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_distribute_list_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_distribute_list_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_distribute_list_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_distribute_list_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_distribute_list_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_distribute_list_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_distribute_list_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_distribute_list_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_distribute_list_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_distribute_list_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_distribute_list_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_distribute_list_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_distribute_list_cmd);

	/* "neighbor prefix-list" commands. */
	install_element(BGP_NODE, &neighbor_prefix_list_hidden_cmd);
	install_element(BGP_NODE, &no_neighbor_prefix_list_hidden_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_prefix_list_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_prefix_list_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_prefix_list_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_prefix_list_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_prefix_list_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_prefix_list_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_prefix_list_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_prefix_list_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_prefix_list_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_prefix_list_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_prefix_list_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_prefix_list_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_prefix_list_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_prefix_list_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_prefix_list_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_prefix_list_cmd);
	install_element(BGP_FLOWSPECV4_NODE, &neighbor_prefix_list_cmd);
	install_element(BGP_FLOWSPECV4_NODE, &no_neighbor_prefix_list_cmd);
	install_element(BGP_FLOWSPECV6_NODE, &neighbor_prefix_list_cmd);
	install_element(BGP_FLOWSPECV6_NODE, &no_neighbor_prefix_list_cmd);

	/* "neighbor filter-list" commands. */
	install_element(BGP_NODE, &neighbor_filter_list_hidden_cmd);
	install_element(BGP_NODE, &no_neighbor_filter_list_hidden_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_filter_list_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_filter_list_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_filter_list_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_filter_list_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_filter_list_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_filter_list_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_filter_list_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_filter_list_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_filter_list_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_filter_list_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_filter_list_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_filter_list_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_filter_list_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_filter_list_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_filter_list_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_filter_list_cmd);
	install_element(BGP_FLOWSPECV4_NODE, &neighbor_filter_list_cmd);
	install_element(BGP_FLOWSPECV4_NODE, &no_neighbor_filter_list_cmd);
	install_element(BGP_FLOWSPECV6_NODE, &neighbor_filter_list_cmd);
	install_element(BGP_FLOWSPECV6_NODE, &no_neighbor_filter_list_cmd);

	/* "neighbor route-map" commands. */
	install_element(BGP_NODE, &neighbor_route_map_hidden_cmd);
	install_element(BGP_NODE, &no_neighbor_route_map_hidden_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_route_map_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_route_map_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_route_map_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_route_map_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_route_map_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_route_map_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_route_map_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_route_map_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_route_map_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_route_map_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_route_map_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_route_map_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_route_map_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_route_map_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_route_map_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_route_map_cmd);
	install_element(BGP_FLOWSPECV4_NODE, &neighbor_route_map_cmd);
	install_element(BGP_FLOWSPECV4_NODE, &no_neighbor_route_map_cmd);
	install_element(BGP_FLOWSPECV6_NODE, &neighbor_route_map_cmd);
	install_element(BGP_FLOWSPECV6_NODE, &no_neighbor_route_map_cmd);
	install_element(BGP_EVPN_NODE, &neighbor_route_map_cmd);
	install_element(BGP_EVPN_NODE, &no_neighbor_route_map_cmd);

	/* "neighbor unsuppress-map" commands. */
	install_element(BGP_NODE, &neighbor_unsuppress_map_hidden_cmd);
	install_element(BGP_NODE, &no_neighbor_unsuppress_map_hidden_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_unsuppress_map_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_unsuppress_map_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_unsuppress_map_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_unsuppress_map_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_unsuppress_map_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_unsuppress_map_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_unsuppress_map_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_unsuppress_map_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_unsuppress_map_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_unsuppress_map_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_unsuppress_map_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_unsuppress_map_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_unsuppress_map_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_unsuppress_map_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_unsuppress_map_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_unsuppress_map_cmd);

	/* "neighbor advertise-map" commands. */
	install_element(BGP_NODE, &bgp_condadv_period_cmd);
	install_element(BGP_NODE, &neighbor_advertise_map_hidden_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_advertise_map_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_advertise_map_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_advertise_map_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_advertise_map_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_advertise_map_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_advertise_map_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_advertise_map_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_advertise_map_cmd);

	/* bgp default-originate timer */
	install_element(BGP_NODE, &bgp_def_originate_eval_cmd);

	/* neighbor maximum-prefix-out commands. */
	install_element(BGP_NODE, &neighbor_maximum_prefix_out_cmd);
	install_element(BGP_NODE, &no_neighbor_maximum_prefix_out_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_maximum_prefix_out_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_maximum_prefix_out_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_maximum_prefix_out_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_maximum_prefix_out_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_maximum_prefix_out_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_maximum_prefix_out_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_maximum_prefix_out_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_maximum_prefix_out_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_maximum_prefix_out_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_maximum_prefix_out_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_maximum_prefix_out_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_maximum_prefix_out_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_maximum_prefix_out_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_maximum_prefix_out_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_maximum_prefix_out_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_maximum_prefix_out_cmd);

	/* "neighbor maximum-prefix" commands. */
	install_element(BGP_NODE, &neighbor_maximum_prefix_hidden_cmd);
	install_element(BGP_NODE,
			&neighbor_maximum_prefix_threshold_hidden_cmd);
	install_element(BGP_NODE, &neighbor_maximum_prefix_warning_hidden_cmd);
	install_element(BGP_NODE,
			&neighbor_maximum_prefix_threshold_warning_hidden_cmd);
	install_element(BGP_NODE, &neighbor_maximum_prefix_restart_hidden_cmd);
	install_element(BGP_NODE,
			&neighbor_maximum_prefix_threshold_restart_hidden_cmd);
	install_element(BGP_NODE, &no_neighbor_maximum_prefix_hidden_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_maximum_prefix_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_maximum_prefix_threshold_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_maximum_prefix_warning_cmd);
	install_element(BGP_IPV4_NODE,
			&neighbor_maximum_prefix_threshold_warning_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_maximum_prefix_restart_cmd);
	install_element(BGP_IPV4_NODE,
			&neighbor_maximum_prefix_threshold_restart_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_maximum_prefix_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_maximum_prefix_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_maximum_prefix_threshold_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_maximum_prefix_warning_cmd);
	install_element(BGP_IPV4M_NODE,
			&neighbor_maximum_prefix_threshold_warning_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_maximum_prefix_restart_cmd);
	install_element(BGP_IPV4M_NODE,
			&neighbor_maximum_prefix_threshold_restart_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_maximum_prefix_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_maximum_prefix_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_maximum_prefix_threshold_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_maximum_prefix_warning_cmd);
	install_element(BGP_IPV4L_NODE,
			&neighbor_maximum_prefix_threshold_warning_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_maximum_prefix_restart_cmd);
	install_element(BGP_IPV4L_NODE,
			&neighbor_maximum_prefix_threshold_restart_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_maximum_prefix_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_maximum_prefix_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_maximum_prefix_threshold_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_maximum_prefix_warning_cmd);
	install_element(BGP_IPV6_NODE,
			&neighbor_maximum_prefix_threshold_warning_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_maximum_prefix_restart_cmd);
	install_element(BGP_IPV6_NODE,
			&neighbor_maximum_prefix_threshold_restart_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_maximum_prefix_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_maximum_prefix_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_maximum_prefix_threshold_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_maximum_prefix_warning_cmd);
	install_element(BGP_IPV6M_NODE,
			&neighbor_maximum_prefix_threshold_warning_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_maximum_prefix_restart_cmd);
	install_element(BGP_IPV6M_NODE,
			&neighbor_maximum_prefix_threshold_restart_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_maximum_prefix_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_maximum_prefix_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_maximum_prefix_threshold_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_maximum_prefix_warning_cmd);
	install_element(BGP_IPV6L_NODE,
			&neighbor_maximum_prefix_threshold_warning_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_maximum_prefix_restart_cmd);
	install_element(BGP_IPV6L_NODE,
			&neighbor_maximum_prefix_threshold_restart_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_maximum_prefix_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_maximum_prefix_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_maximum_prefix_threshold_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_maximum_prefix_warning_cmd);
	install_element(BGP_VPNV4_NODE,
			&neighbor_maximum_prefix_threshold_warning_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_maximum_prefix_restart_cmd);
	install_element(BGP_VPNV4_NODE,
			&neighbor_maximum_prefix_threshold_restart_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_maximum_prefix_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_maximum_prefix_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_maximum_prefix_threshold_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_maximum_prefix_warning_cmd);
	install_element(BGP_VPNV6_NODE,
			&neighbor_maximum_prefix_threshold_warning_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_maximum_prefix_restart_cmd);
	install_element(BGP_VPNV6_NODE,
			&neighbor_maximum_prefix_threshold_restart_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_maximum_prefix_cmd);
	install_element(BGP_EVPN_NODE, &neighbor_maximum_prefix_cmd);
	install_element(BGP_EVPN_NODE, &neighbor_maximum_prefix_threshold_cmd);
	install_element(BGP_EVPN_NODE, &neighbor_maximum_prefix_warning_cmd);
	install_element(BGP_EVPN_NODE,
			&neighbor_maximum_prefix_threshold_warning_cmd);
	install_element(BGP_EVPN_NODE, &neighbor_maximum_prefix_restart_cmd);
	install_element(BGP_EVPN_NODE,
			&neighbor_maximum_prefix_threshold_restart_cmd);
	install_element(BGP_EVPN_NODE, &no_neighbor_maximum_prefix_cmd);

	/* "neighbor allowas-in" */
	install_element(BGP_NODE, &neighbor_allowas_in_hidden_cmd);
	install_element(BGP_NODE, &no_neighbor_allowas_in_hidden_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_allowas_in_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_allowas_in_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_allowas_in_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_allowas_in_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_allowas_in_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_allowas_in_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_allowas_in_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_allowas_in_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_allowas_in_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_allowas_in_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_allowas_in_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_allowas_in_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_allowas_in_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_allowas_in_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_allowas_in_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_allowas_in_cmd);
	install_element(BGP_EVPN_NODE, &neighbor_allowas_in_cmd);
	install_element(BGP_EVPN_NODE, &no_neighbor_allowas_in_cmd);

	/* neighbor accept-own */
	install_element(BGP_VPNV4_NODE, &neighbor_accept_own_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_accept_own_cmd);

	/* "neighbor soo" */
	install_element(BGP_IPV4_NODE, &neighbor_soo_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_soo_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_soo_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_soo_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_soo_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_soo_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_soo_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_soo_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_soo_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_soo_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_soo_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_soo_cmd);
	install_element(BGP_VPNV4_NODE, &neighbor_soo_cmd);
	install_element(BGP_VPNV4_NODE, &no_neighbor_soo_cmd);
	install_element(BGP_VPNV6_NODE, &neighbor_soo_cmd);
	install_element(BGP_VPNV6_NODE, &no_neighbor_soo_cmd);
	install_element(BGP_EVPN_NODE, &neighbor_soo_cmd);
	install_element(BGP_EVPN_NODE, &no_neighbor_soo_cmd);

	/* "neighbor dampening" commands. */
	install_element(BGP_NODE, &neighbor_damp_cmd);
	install_element(BGP_NODE, &no_neighbor_damp_cmd);
	install_element(BGP_IPV4_NODE, &neighbor_damp_cmd);
	install_element(BGP_IPV4_NODE, &no_neighbor_damp_cmd);
	install_element(BGP_IPV4M_NODE, &neighbor_damp_cmd);
	install_element(BGP_IPV4M_NODE, &no_neighbor_damp_cmd);
	install_element(BGP_IPV4L_NODE, &neighbor_damp_cmd);
	install_element(BGP_IPV4L_NODE, &no_neighbor_damp_cmd);
	install_element(BGP_IPV6_NODE, &neighbor_damp_cmd);
	install_element(BGP_IPV6_NODE, &no_neighbor_damp_cmd);
	install_element(BGP_IPV6M_NODE, &neighbor_damp_cmd);
	install_element(BGP_IPV6M_NODE, &no_neighbor_damp_cmd);
	install_element(BGP_IPV6L_NODE, &neighbor_damp_cmd);
	install_element(BGP_IPV6L_NODE, &no_neighbor_damp_cmd);
	install_element(VIEW_NODE, &show_ip_bgp_neighbor_damp_param_cmd);

	/* address-family commands. */
	install_element(BGP_NODE, &address_family_ipv4_safi_cmd);
	install_element(BGP_NODE, &address_family_ipv6_safi_cmd);
#ifdef KEEP_OLD_VPN_COMMANDS
	install_element(BGP_NODE, &address_family_vpnv4_cmd);
	install_element(BGP_NODE, &address_family_vpnv6_cmd);
#endif /* KEEP_OLD_VPN_COMMANDS */

	install_element(BGP_NODE, &address_family_evpn_cmd);

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
	install_element(BGP_EVPN_NODE, &exit_address_family_cmd);

	/* BGP retain all route-target */
	install_element(BGP_VPNV4_NODE, &bgp_retain_route_target_cmd);
	install_element(BGP_VPNV6_NODE, &bgp_retain_route_target_cmd);

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

	install_element(VIEW_NODE, &show_ip_bgp_neighbors_graceful_restart_cmd);

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

	/* "redistribute" commands.  */
	install_element(BGP_NODE, &bgp_redistribute_ipv4_hidden_cmd);
	install_element(BGP_NODE, &no_bgp_redistribute_ipv4_hidden_cmd);
	install_element(BGP_NODE, &bgp_redistribute_ipv4_rmap_hidden_cmd);
	install_element(BGP_NODE, &bgp_redistribute_ipv4_metric_hidden_cmd);
	install_element(BGP_NODE,
			&bgp_redistribute_ipv4_rmap_metric_hidden_cmd);
	install_element(BGP_NODE,
			&bgp_redistribute_ipv4_metric_rmap_hidden_cmd);
	install_element(BGP_NODE, &bgp_redistribute_ipv4_ospf_hidden_cmd);
	install_element(BGP_NODE, &no_bgp_redistribute_ipv4_ospf_hidden_cmd);
	install_element(BGP_NODE, &bgp_redistribute_ipv4_ospf_rmap_hidden_cmd);
	install_element(BGP_NODE,
			&bgp_redistribute_ipv4_ospf_metric_hidden_cmd);
	install_element(BGP_NODE,
			&bgp_redistribute_ipv4_ospf_rmap_metric_hidden_cmd);
	install_element(BGP_NODE,
			&bgp_redistribute_ipv4_ospf_metric_rmap_hidden_cmd);
	install_element(BGP_IPV4_NODE, &bgp_redistribute_ipv4_cmd);
	install_element(BGP_IPV4_NODE, &no_bgp_redistribute_ipv4_cmd);
	install_element(BGP_IPV4_NODE, &bgp_redistribute_ipv4_rmap_cmd);
	install_element(BGP_IPV4_NODE, &bgp_redistribute_ipv4_metric_cmd);
	install_element(BGP_IPV4_NODE, &bgp_redistribute_ipv4_rmap_metric_cmd);
	install_element(BGP_IPV4_NODE, &bgp_redistribute_ipv4_metric_rmap_cmd);
	install_element(BGP_IPV4_NODE, &bgp_redistribute_ipv4_ospf_cmd);
	install_element(BGP_IPV4_NODE, &no_bgp_redistribute_ipv4_ospf_cmd);
	install_element(BGP_IPV4_NODE, &bgp_redistribute_ipv4_ospf_rmap_cmd);
	install_element(BGP_IPV4_NODE, &bgp_redistribute_ipv4_ospf_metric_cmd);
	install_element(BGP_IPV4_NODE,
			&bgp_redistribute_ipv4_ospf_rmap_metric_cmd);
	install_element(BGP_IPV4_NODE,
			&bgp_redistribute_ipv4_ospf_metric_rmap_cmd);
	install_element(BGP_IPV6_NODE, &bgp_redistribute_ipv6_cmd);
	install_element(BGP_IPV6_NODE, &no_bgp_redistribute_ipv6_cmd);
	install_element(BGP_IPV6_NODE, &bgp_redistribute_ipv6_rmap_cmd);
	install_element(BGP_IPV6_NODE, &bgp_redistribute_ipv6_metric_cmd);
	install_element(BGP_IPV6_NODE, &bgp_redistribute_ipv6_rmap_metric_cmd);
	install_element(BGP_IPV6_NODE, &bgp_redistribute_ipv6_metric_rmap_cmd);
	install_element(BGP_IPV6_NODE, &bgp_redistribute_ipv6_table_cmd);
	install_element(BGP_IPV6_NODE, &no_bgp_redistribute_ipv6_table_cmd);

	/* import|export vpn [route-map RMAP_NAME] */
	install_element(BGP_IPV4_NODE, &bgp_imexport_vpn_cmd);
	install_element(BGP_IPV6_NODE, &bgp_imexport_vpn_cmd);

	install_element(BGP_IPV4_NODE, &bgp_imexport_vrf_cmd);
	install_element(BGP_IPV6_NODE, &bgp_imexport_vrf_cmd);

	/* ttl_security commands */
	install_element(BGP_NODE, &neighbor_ttl_security_cmd);
	install_element(BGP_NODE, &no_neighbor_ttl_security_cmd);

	/* "bgp tcp-keepalive" commands */
	install_element(BGP_NODE, &bgp_tcp_keepalive_cmd);
	install_element(BGP_NODE, &no_bgp_tcp_keepalive_cmd);

	/* "show [ip] bgp memory" commands. */
	install_element(VIEW_NODE, &show_bgp_memory_cmd);

	/* "show bgp martian next-hop" */
	install_element(VIEW_NODE, &show_bgp_martian_nexthop_db_cmd);

	install_element(VIEW_NODE, &show_bgp_mac_hash_cmd);

	/* "show [ip] bgp views" commands. */
	install_element(VIEW_NODE, &show_bgp_views_cmd);

	/* "show [ip] bgp vrfs" commands. */
	install_element(VIEW_NODE, &show_bgp_vrfs_cmd);

	/* Community-list. */
	community_list_vty();

	community_alias_vty();

	/* vpn-policy commands */
	install_element(BGP_IPV4_NODE, &af_rd_vpn_export_cmd);
	install_element(BGP_IPV6_NODE, &af_rd_vpn_export_cmd);
	install_element(BGP_IPV4_NODE, &af_label_vpn_export_cmd);
	install_element(BGP_IPV6_NODE, &af_label_vpn_export_cmd);
	install_element(BGP_IPV4_NODE,
			&af_label_vpn_export_allocation_mode_cmd);
	install_element(BGP_IPV6_NODE,
			&af_label_vpn_export_allocation_mode_cmd);
	install_element(BGP_IPV4_NODE, &af_nexthop_vpn_export_cmd);
	install_element(BGP_IPV6_NODE, &af_nexthop_vpn_export_cmd);
	install_element(BGP_IPV4_NODE, &af_rt_vpn_imexport_cmd);
	install_element(BGP_IPV6_NODE, &af_rt_vpn_imexport_cmd);
	install_element(BGP_IPV4_NODE, &af_route_map_vpn_imexport_cmd);
	install_element(BGP_IPV6_NODE, &af_route_map_vpn_imexport_cmd);
	install_element(BGP_IPV4_NODE, &af_import_vrf_route_map_cmd);
	install_element(BGP_IPV6_NODE, &af_import_vrf_route_map_cmd);

	install_element(BGP_IPV4_NODE, &af_routetarget_import_cmd);
	install_element(BGP_IPV6_NODE, &af_routetarget_import_cmd);

	install_element(BGP_IPV4_NODE, &af_no_rd_vpn_export_cmd);
	install_element(BGP_IPV6_NODE, &af_no_rd_vpn_export_cmd);
	install_element(BGP_IPV4_NODE, &af_no_label_vpn_export_cmd);
	install_element(BGP_IPV6_NODE, &af_no_label_vpn_export_cmd);
	install_element(BGP_IPV4_NODE, &af_no_rt_vpn_imexport_cmd);
	install_element(BGP_IPV6_NODE, &af_no_rt_vpn_imexport_cmd);
	install_element(BGP_IPV4_NODE, &af_no_route_map_vpn_imexport_cmd);
	install_element(BGP_IPV6_NODE, &af_no_route_map_vpn_imexport_cmd);
	install_element(BGP_IPV4_NODE, &af_no_import_vrf_route_map_cmd);
	install_element(BGP_IPV6_NODE, &af_no_import_vrf_route_map_cmd);

	/* tcp-mss command */
	install_element(BGP_NODE, &neighbor_tcp_mss_cmd);
	install_element(BGP_NODE, &no_neighbor_tcp_mss_cmd);

	/* srv6 commands */
	install_element(VIEW_NODE, &show_bgp_srv6_cmd);
	install_element(BGP_NODE, &bgp_segment_routing_srv6_cmd);
	install_element(BGP_NODE, &no_bgp_segment_routing_srv6_cmd);
	install_element(BGP_SRV6_NODE, &bgp_srv6_locator_cmd);
	install_element(BGP_SRV6_NODE, &no_bgp_srv6_locator_cmd);
	install_element(BGP_IPV4_NODE, &af_sid_vpn_export_cmd);
	install_element(BGP_IPV6_NODE, &af_sid_vpn_export_cmd);
	install_element(BGP_NODE, &bgp_sid_vpn_export_cmd);
	install_element(BGP_NODE, &no_bgp_sid_vpn_export_cmd);

	bgp_vty_if_init();
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

/* Display error string.  */
static void community_list_perror(struct vty *vty, int ret)
{
	switch (ret) {
	case COMMUNITY_LIST_ERR_MALFORMED_VAL:
		vty_out(vty, "%% Malformed community-list value\n");
		break;
	case COMMUNITY_LIST_ERR_STANDARD_CONFLICT:
		vty_out(vty,
			"%% Community name conflict, previously defined as standard community\n");
		break;
	case COMMUNITY_LIST_ERR_EXPANDED_CONFLICT:
		vty_out(vty,
			"%% Community name conflict, previously defined as expanded community\n");
		break;
	}
}

/* "community-list" keyword help string.  */
#define COMMUNITY_LIST_STR "Add a community list entry\n"

/*community-list standard */
DEFUN (community_list_standard,
       bgp_community_list_standard_cmd,
       "bgp community-list <(1-99)|standard COMMUNITY_LIST_NAME> [seq (0-4294967295)] <deny|permit> AA:NN...",
       BGP_STR
       COMMUNITY_LIST_STR
       "Community list number (standard)\n"
       "Add an standard community-list entry\n"
       "Community list name\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       COMMUNITY_VAL_STR)
{
	char *cl_name_or_number = NULL;
	char *seq = NULL;
	int direct = 0;
	int style = COMMUNITY_LIST_STANDARD;
	int idx = 0;

	if (argv_find(argv, argc, "(0-4294967295)", &idx))
		seq = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "(1-99)", &idx);
	argv_find(argv, argc, "COMMUNITY_LIST_NAME", &idx);
	cl_name_or_number = argv[idx]->arg;
	direct = argv_find(argv, argc, "permit", &idx) ? COMMUNITY_PERMIT
						       : COMMUNITY_DENY;
	argv_find(argv, argc, "AA:NN", &idx);
	char *str = argv_concat(argv, argc, idx);

	assert(str);
	int ret = community_list_set(bgp_clist, cl_name_or_number, str, seq,
				     direct, style);

	XFREE(MTYPE_TMP, str);

	if (ret < 0) {
		/* Display error string.  */
		community_list_perror(vty, ret);
		return CMD_WARNING_CONFIG_FAILED;
	}

	return CMD_SUCCESS;
}

DEFUN (no_community_list_standard_all,
       no_bgp_community_list_standard_all_cmd,
       "no bgp community-list <(1-99)|standard COMMUNITY_LIST_NAME> [seq (0-4294967295)] <deny|permit> AA:NN...",
       NO_STR
       BGP_STR
       COMMUNITY_LIST_STR
       "Community list number (standard)\n"
       "Add an standard community-list entry\n"
       "Community list name\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       COMMUNITY_VAL_STR)
{
	char *cl_name_or_number = NULL;
	char *str = NULL;
	int direct = 0;
	int style = COMMUNITY_LIST_STANDARD;
	char *seq = NULL;
	int idx = 0;

	if (argv_find(argv, argc, "(0-4294967295)", &idx))
		seq = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "permit", &idx);
	argv_find(argv, argc, "deny", &idx);

	if (idx) {
		direct = argv_find(argv, argc, "permit", &idx)
				 ? COMMUNITY_PERMIT
				 : COMMUNITY_DENY;

		idx = 0;
		argv_find(argv, argc, "AA:NN", &idx);
		str = argv_concat(argv, argc, idx);
	}

	idx = 0;
	argv_find(argv, argc, "(1-99)", &idx);
	argv_find(argv, argc, "COMMUNITY_LIST_NAME", &idx);
	cl_name_or_number = argv[idx]->arg;

	community_list_unset(bgp_clist, cl_name_or_number, str, seq, direct,
			     style);

	XFREE(MTYPE_TMP, str);

	return CMD_SUCCESS;
}

ALIAS(no_community_list_standard_all, no_bgp_community_list_standard_all_list_cmd,
      "no bgp community-list <(1-99)|standard COMMUNITY_LIST_NAME>",
      NO_STR BGP_STR COMMUNITY_LIST_STR
      "Community list number (standard)\n"
      "Add an standard community-list entry\n"
      "Community list name\n")

/*community-list expanded */
DEFUN (community_list_expanded_all,
       bgp_community_list_expanded_all_cmd,
       "bgp community-list <(100-500)|expanded COMMUNITY_LIST_NAME> [seq (0-4294967295)] <deny|permit> AA:NN...",
       BGP_STR
       COMMUNITY_LIST_STR
       "Community list number (expanded)\n"
       "Add an expanded community-list entry\n"
       "Community list name\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       COMMUNITY_VAL_STR)
{
	char *cl_name_or_number = NULL;
	char *seq = NULL;
	int direct = 0;
	int style = COMMUNITY_LIST_EXPANDED;
	int idx = 0;

	if (argv_find(argv, argc, "(0-4294967295)", &idx))
		seq = argv[idx]->arg;

	idx = 0;

	argv_find(argv, argc, "(100-500)", &idx);
	argv_find(argv, argc, "COMMUNITY_LIST_NAME", &idx);
	cl_name_or_number = argv[idx]->arg;
	direct = argv_find(argv, argc, "permit", &idx) ? COMMUNITY_PERMIT
						       : COMMUNITY_DENY;
	argv_find(argv, argc, "AA:NN", &idx);
	char *str = argv_concat(argv, argc, idx);

	assert(str);
	int ret = community_list_set(bgp_clist, cl_name_or_number, str, seq,
				     direct, style);

	XFREE(MTYPE_TMP, str);

	if (ret < 0) {
		/* Display error string.  */
		community_list_perror(vty, ret);
		return CMD_WARNING_CONFIG_FAILED;
	}

	return CMD_SUCCESS;
}

DEFUN (no_community_list_expanded_all,
       no_bgp_community_list_expanded_all_cmd,
       "no bgp community-list <(100-500)|expanded COMMUNITY_LIST_NAME> [seq (0-4294967295)] <deny|permit> AA:NN...",
       NO_STR
       BGP_STR
       COMMUNITY_LIST_STR
       "Community list number (expanded)\n"
       "Add an expanded community-list entry\n"
       "Community list name\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       COMMUNITY_VAL_STR)
{
	char *cl_name_or_number = NULL;
	char *seq = NULL;
	char *str = NULL;
	int direct = 0;
	int style = COMMUNITY_LIST_EXPANDED;
	int idx = 0;

	if (argv_find(argv, argc, "(0-4294967295)", &idx))
		seq = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "permit", &idx);
	argv_find(argv, argc, "deny", &idx);

	if (idx) {
		direct = argv_find(argv, argc, "permit", &idx)
				 ? COMMUNITY_PERMIT
				 : COMMUNITY_DENY;

		idx = 0;
		argv_find(argv, argc, "AA:NN", &idx);
		str = argv_concat(argv, argc, idx);
	}

	idx = 0;
	argv_find(argv, argc, "(100-500)", &idx);
	argv_find(argv, argc, "COMMUNITY_LIST_NAME", &idx);
	cl_name_or_number = argv[idx]->arg;

	community_list_unset(bgp_clist, cl_name_or_number, str, seq, direct,
			     style);

	XFREE(MTYPE_TMP, str);

	return CMD_SUCCESS;
}

ALIAS(no_community_list_expanded_all,
      no_bgp_community_list_expanded_all_list_cmd,
      "no bgp community-list <(100-500)|expanded COMMUNITY_LIST_NAME>",
      NO_STR BGP_STR COMMUNITY_LIST_STR
      "Community list number (expanded)\n"
      "Add an expanded community-list entry\n"
      "Community list name\n")

/* Return configuration string of community-list entry.  */
static const char *community_list_config_str(struct community_entry *entry)
{
	const char *str;

	if (entry->style == COMMUNITY_LIST_STANDARD)
		str = community_str(entry->u.com, false, false);
	else if (entry->style == LARGE_COMMUNITY_LIST_STANDARD)
		str = lcommunity_str(entry->u.lcom, false, false);
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

/*
 * Large Community code.
 */
static int lcommunity_list_set_vty(struct vty *vty, int argc,
				   struct cmd_token **argv, int style,
				   int reject_all_digit_name)
{
	int ret;
	int direct;
	char *str;
	int idx = 0;
	char *cl_name;
	char *seq = NULL;

	if (argv_find(argv, argc, "(0-4294967295)", &idx))
		seq = argv[idx]->arg;

	idx = 0;
	direct = argv_find(argv, argc, "permit", &idx) ? COMMUNITY_PERMIT
						       : COMMUNITY_DENY;

	/* All digit name check.  */
	idx = 0;
	argv_find(argv, argc, "LCOMMUNITY_LIST_NAME", &idx);
	argv_find(argv, argc, "(1-99)", &idx);
	argv_find(argv, argc, "(100-500)", &idx);
	cl_name = argv[idx]->arg;
	if (reject_all_digit_name && all_digit(cl_name)) {
		vty_out(vty, "%% Community name cannot have all digits\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	idx = 0;
	argv_find(argv, argc, "AA:BB:CC", &idx);
	argv_find(argv, argc, "LINE", &idx);
	/* Concat community string argument. */
	if (idx)
		str = argv_concat(argv, argc, idx);
	else
		str = NULL;

	ret = lcommunity_list_set(bgp_clist, cl_name, str, seq, direct, style);

	/* Free temporary community list string allocated by
	   argv_concat().  */
	XFREE(MTYPE_TMP, str);

	if (ret < 0) {
		community_list_perror(vty, ret);
		return CMD_WARNING_CONFIG_FAILED;
	}
	return CMD_SUCCESS;
}

static int lcommunity_list_unset_vty(struct vty *vty, int argc,
				     struct cmd_token **argv, int style)
{
	int direct = 0;
	char *str = NULL;
	int idx = 0;
	char *seq = NULL;

	if (argv_find(argv, argc, "(0-4294967295)", &idx))
		seq = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "permit", &idx);
	argv_find(argv, argc, "deny", &idx);

	if (idx) {
		/* Check the list direct. */
		if (strncmp(argv[idx]->arg, "p", 1) == 0)
			direct = COMMUNITY_PERMIT;
		else
			direct = COMMUNITY_DENY;

		idx = 0;
		argv_find(argv, argc, "LINE", &idx);
		argv_find(argv, argc, "AA:AA:NN", &idx);
		/* Concat community string argument.  */
		str = argv_concat(argv, argc, idx);
	}

	idx = 0;
	argv_find(argv, argc, "(1-99)", &idx);
	argv_find(argv, argc, "(100-500)", &idx);
	argv_find(argv, argc, "LCOMMUNITY_LIST_NAME", &idx);

	/* Unset community list.  */
	lcommunity_list_unset(bgp_clist, argv[idx]->arg, str, seq, direct,
			      style);

	/* Free temporary community list string allocated by
	   argv_concat().  */
	XFREE(MTYPE_TMP, str);

	return CMD_SUCCESS;
}

/* "large-community-list" keyword help string.  */
#define LCOMMUNITY_LIST_STR "Add a large community list entry\n"
#define LCOMMUNITY_VAL_STR  "large community in 'aa:bb:cc' format\n"

DEFUN (lcommunity_list_standard,
       bgp_lcommunity_list_standard_cmd,
       "bgp large-community-list (1-99) [seq (0-4294967295)] <deny|permit> AA:BB:CC...",
       BGP_STR
       LCOMMUNITY_LIST_STR
       "Large Community list number (standard)\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify large community to reject\n"
       "Specify large community to accept\n"
       LCOMMUNITY_VAL_STR)
{
	return lcommunity_list_set_vty(vty, argc, argv,
				       LARGE_COMMUNITY_LIST_STANDARD, 0);
}

DEFUN (lcommunity_list_expanded,
       bgp_lcommunity_list_expanded_cmd,
       "bgp large-community-list (100-500) [seq (0-4294967295)] <deny|permit> LINE...",
       BGP_STR
       LCOMMUNITY_LIST_STR
       "Large Community list number (expanded)\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify large community to reject\n"
       "Specify large community to accept\n"
       "An ordered list as a regular-expression\n")
{
	return lcommunity_list_set_vty(vty, argc, argv,
				       LARGE_COMMUNITY_LIST_EXPANDED, 0);
}

DEFUN (lcommunity_list_name_standard,
       bgp_lcommunity_list_name_standard_cmd,
       "bgp large-community-list standard LCOMMUNITY_LIST_NAME [seq (0-4294967295)] <deny|permit> AA:BB:CC...",
       BGP_STR
       LCOMMUNITY_LIST_STR
       "Specify standard large-community-list\n"
       "Large Community list name\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify large community to reject\n"
       "Specify large community to accept\n"
       LCOMMUNITY_VAL_STR)
{
	return lcommunity_list_set_vty(vty, argc, argv,
				       LARGE_COMMUNITY_LIST_STANDARD, 1);
}

DEFUN (lcommunity_list_name_expanded,
       bgp_lcommunity_list_name_expanded_cmd,
       "bgp large-community-list expanded LCOMMUNITY_LIST_NAME [seq (0-4294967295)] <deny|permit> LINE...",
       BGP_STR
       LCOMMUNITY_LIST_STR
       "Specify expanded large-community-list\n"
       "Large Community list name\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify large community to reject\n"
       "Specify large community to accept\n"
       "An ordered list as a regular-expression\n")
{
	return lcommunity_list_set_vty(vty, argc, argv,
				       LARGE_COMMUNITY_LIST_EXPANDED, 1);
}

DEFUN (no_lcommunity_list_all,
       no_bgp_lcommunity_list_all_cmd,
       "no bgp large-community-list <(1-99)|(100-500)|LCOMMUNITY_LIST_NAME>",
       NO_STR
       BGP_STR
       LCOMMUNITY_LIST_STR
       "Large Community list number (standard)\n"
       "Large Community list number (expanded)\n"
       "Large Community list name\n")
{
	return lcommunity_list_unset_vty(vty, argc, argv,
					 LARGE_COMMUNITY_LIST_STANDARD);
}

DEFUN (no_lcommunity_list_name_standard_all,
       no_bgp_lcommunity_list_name_standard_all_cmd,
       "no bgp large-community-list standard LCOMMUNITY_LIST_NAME",
       NO_STR
       BGP_STR
       LCOMMUNITY_LIST_STR
       "Specify standard large-community-list\n"
       "Large Community list name\n")
{
	return lcommunity_list_unset_vty(vty, argc, argv,
					 LARGE_COMMUNITY_LIST_STANDARD);
}

DEFUN (no_lcommunity_list_name_expanded_all,
       no_bgp_lcommunity_list_name_expanded_all_cmd,
       "no bgp large-community-list expanded LCOMMUNITY_LIST_NAME",
       NO_STR
       BGP_STR
       LCOMMUNITY_LIST_STR
       "Specify expanded large-community-list\n"
       "Large Community list name\n")
{
	return lcommunity_list_unset_vty(vty, argc, argv,
					 LARGE_COMMUNITY_LIST_EXPANDED);
}

DEFUN (no_lcommunity_list_standard,
       no_bgp_lcommunity_list_standard_cmd,
       "no bgp large-community-list (1-99) [seq (0-4294967295)] <deny|permit> AA:AA:NN...",
       NO_STR
       BGP_STR
       LCOMMUNITY_LIST_STR
       "Large Community list number (standard)\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify large community to reject\n"
       "Specify large community to accept\n"
       LCOMMUNITY_VAL_STR)
{
	return lcommunity_list_unset_vty(vty, argc, argv,
					 LARGE_COMMUNITY_LIST_STANDARD);
}

DEFUN (no_lcommunity_list_expanded,
       no_bgp_lcommunity_list_expanded_cmd,
       "no bgp large-community-list (100-500) [seq (0-4294967295)] <deny|permit> LINE...",
       NO_STR
       BGP_STR
       LCOMMUNITY_LIST_STR
       "Large Community list number (expanded)\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify large community to reject\n"
       "Specify large community to accept\n"
       "An ordered list as a regular-expression\n")
{
	return lcommunity_list_unset_vty(vty, argc, argv,
					 LARGE_COMMUNITY_LIST_EXPANDED);
}

DEFUN (no_lcommunity_list_name_standard,
       no_bgp_lcommunity_list_name_standard_cmd,
       "no bgp large-community-list standard LCOMMUNITY_LIST_NAME [seq (0-4294967295)] <deny|permit> AA:AA:NN...",
       NO_STR
       BGP_STR
       LCOMMUNITY_LIST_STR
       "Specify standard large-community-list\n"
       "Large Community list name\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify large community to reject\n"
       "Specify large community to accept\n"
       LCOMMUNITY_VAL_STR)
{
	return lcommunity_list_unset_vty(vty, argc, argv,
					 LARGE_COMMUNITY_LIST_STANDARD);
}

DEFUN (no_lcommunity_list_name_expanded,
       no_bgp_lcommunity_list_name_expanded_cmd,
       "no bgp large-community-list expanded LCOMMUNITY_LIST_NAME [seq (0-4294967295)] <deny|permit> LINE...",
       NO_STR
       BGP_STR
       LCOMMUNITY_LIST_STR
       "Specify expanded large-community-list\n"
       "Large community list name\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify large community to reject\n"
       "Specify large community to accept\n"
       "An ordered list as a regular-expression\n")
{
	return lcommunity_list_unset_vty(vty, argc, argv,
					 LARGE_COMMUNITY_LIST_EXPANDED);
}

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
#define EXTCOMMUNITY_LIST_STR "Add a extended community list entry\n"
#define EXTCOMMUNITY_VAL_STR  "Extended community attribute in 'rt aa:nn_or_IPaddr:nn' OR 'soo aa:nn_or_IPaddr:nn' format\n"

DEFUN (extcommunity_list_standard,
       bgp_extcommunity_list_standard_cmd,
       "bgp extcommunity-list <(1-99)|standard EXTCOMMUNITY_LIST_NAME> [seq (0-4294967295)] <deny|permit> AA:NN...",
       BGP_STR
       EXTCOMMUNITY_LIST_STR
       "Extended Community list number (standard)\n"
       "Specify standard extcommunity-list\n"
       "Community list name\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       EXTCOMMUNITY_VAL_STR)
{
	int style = EXTCOMMUNITY_LIST_STANDARD;
	int direct = 0;
	char *cl_number_or_name = NULL;
	char *seq = NULL;

	int idx = 0;

	argv_find(argv, argc, "(1-99)", &idx);
	argv_find(argv, argc, "EXTCOMMUNITY_LIST_NAME", &idx);
	cl_number_or_name = argv[idx]->arg;

	if (argv_find(argv, argc, "(0-4294967295)", &idx))
		seq = argv[idx]->arg;

	direct = argv_find(argv, argc, "permit", &idx) ? COMMUNITY_PERMIT
						       : COMMUNITY_DENY;
	argv_find(argv, argc, "AA:NN", &idx);
	char *str = argv_concat(argv, argc, idx);

	int ret = extcommunity_list_set(bgp_clist, cl_number_or_name, str, seq,
					direct, style);

	XFREE(MTYPE_TMP, str);

	if (ret < 0) {
		community_list_perror(vty, ret);
		return CMD_WARNING_CONFIG_FAILED;
	}

	return CMD_SUCCESS;
}

DEFUN (extcommunity_list_name_expanded,
       bgp_extcommunity_list_name_expanded_cmd,
       "bgp extcommunity-list <(100-500)|expanded EXTCOMMUNITY_LIST_NAME> [seq (0-4294967295)] <deny|permit> LINE...",
       BGP_STR
       EXTCOMMUNITY_LIST_STR
       "Extended Community list number (expanded)\n"
       "Specify expanded extcommunity-list\n"
       "Extended Community list name\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       "An ordered list as a regular-expression\n")
{
	int style = EXTCOMMUNITY_LIST_EXPANDED;
	int direct = 0;
	char *cl_number_or_name = NULL;
	char *seq = NULL;
	int idx = 0;

	argv_find(argv, argc, "(100-500)", &idx);
	argv_find(argv, argc, "EXTCOMMUNITY_LIST_NAME", &idx);
	cl_number_or_name = argv[idx]->arg;

	if (argv_find(argv, argc, "(0-4294967295)", &idx))
		seq = argv[idx]->arg;

	direct = argv_find(argv, argc, "permit", &idx) ? COMMUNITY_PERMIT
						       : COMMUNITY_DENY;
	argv_find(argv, argc, "LINE", &idx);
	char *str = argv_concat(argv, argc, idx);

	int ret = extcommunity_list_set(bgp_clist, cl_number_or_name, str, seq,
					direct, style);

	XFREE(MTYPE_TMP, str);

	if (ret < 0) {
		community_list_perror(vty, ret);
		return CMD_WARNING_CONFIG_FAILED;
	}

	return CMD_SUCCESS;
}

DEFUN (no_extcommunity_list_standard_all,
       no_bgp_extcommunity_list_standard_all_cmd,
       "no bgp extcommunity-list <(1-99)|standard EXTCOMMUNITY_LIST_NAME> [seq (0-4294967295)] <deny|permit> AA:NN...",
       NO_STR
       BGP_STR
       EXTCOMMUNITY_LIST_STR
       "Extended Community list number (standard)\n"
       "Specify standard extcommunity-list\n"
       "Community list name\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       EXTCOMMUNITY_VAL_STR)
{
	int style = EXTCOMMUNITY_LIST_STANDARD;
	int direct = 0;
	char *cl_number_or_name = NULL;
	char *str = NULL;
	char *seq = NULL;
	int idx = 0;

	if (argv_find(argv, argc, "(0-4294967295)", &idx))
		seq = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "permit", &idx);
	argv_find(argv, argc, "deny", &idx);
	if (idx) {
		direct = argv_find(argv, argc, "permit", &idx)
				 ? COMMUNITY_PERMIT
				 : COMMUNITY_DENY;

		idx = 0;
		argv_find(argv, argc, "AA:NN", &idx);
		str = argv_concat(argv, argc, idx);
	}

	idx = 0;
	argv_find(argv, argc, "(1-99)", &idx);
	argv_find(argv, argc, "EXTCOMMUNITY_LIST_NAME", &idx);
	cl_number_or_name = argv[idx]->arg;

	extcommunity_list_unset(bgp_clist, cl_number_or_name, str, seq, direct,
				style);

	XFREE(MTYPE_TMP, str);

	return CMD_SUCCESS;
}

ALIAS(no_extcommunity_list_standard_all,
      no_bgp_extcommunity_list_standard_all_list_cmd,
      "no bgp extcommunity-list <(1-99)|standard EXTCOMMUNITY_LIST_NAME>",
      NO_STR BGP_STR EXTCOMMUNITY_LIST_STR
      "Extended Community list number (standard)\n"
      "Specify standard extcommunity-list\n"
      "Community list name\n")

DEFUN (no_extcommunity_list_expanded_all,
       no_bgp_extcommunity_list_expanded_all_cmd,
       "no bgp extcommunity-list <(100-500)|expanded EXTCOMMUNITY_LIST_NAME> [seq (0-4294967295)] <deny|permit> LINE...",
       NO_STR
       BGP_STR
       EXTCOMMUNITY_LIST_STR
       "Extended Community list number (expanded)\n"
       "Specify expanded extcommunity-list\n"
       "Extended Community list name\n"
       "Sequence number of an entry\n"
       "Sequence number\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       "An ordered list as a regular-expression\n")
{
	int style = EXTCOMMUNITY_LIST_EXPANDED;
	int direct = 0;
	char *cl_number_or_name = NULL;
	char *str = NULL;
	char *seq = NULL;
	int idx = 0;

	if (argv_find(argv, argc, "(0-4294967295)", &idx))
		seq = argv[idx]->arg;

	idx = 0;
	argv_find(argv, argc, "permit", &idx);
	argv_find(argv, argc, "deny", &idx);

	if (idx) {
		direct = argv_find(argv, argc, "permit", &idx)
				 ? COMMUNITY_PERMIT
				 : COMMUNITY_DENY;

		idx = 0;
		argv_find(argv, argc, "LINE", &idx);
		str = argv_concat(argv, argc, idx);
	}

	idx = 0;
	argv_find(argv, argc, "(100-500)", &idx);
	argv_find(argv, argc, "EXTCOMMUNITY_LIST_NAME", &idx);
	cl_number_or_name = argv[idx]->arg;

	extcommunity_list_unset(bgp_clist, cl_number_or_name, str, seq, direct,
				style);

	XFREE(MTYPE_TMP, str);

	return CMD_SUCCESS;
}

ALIAS(no_extcommunity_list_expanded_all,
      no_bgp_extcommunity_list_expanded_all_list_cmd,
      "no bgp extcommunity-list <(100-500)|expanded EXTCOMMUNITY_LIST_NAME>",
      NO_STR BGP_STR EXTCOMMUNITY_LIST_STR
      "Extended Community list number (expanded)\n"
      "Specify expanded extcommunity-list\n"
      "Extended Community list name\n")

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
static int community_list_config_write(struct vty *vty)
{
	struct community_list *list;
	struct community_entry *entry;
	struct community_list_master *cm;
	int write = 0;

	/* Community-list.  */
	cm = community_list_master_lookup(bgp_clist, COMMUNITY_LIST_MASTER);

	for (list = cm->num.head; list; list = list->next)
		for (entry = list->head; entry; entry = entry->next) {
			vty_out(vty,
				"bgp community-list %s seq %" PRId64 " %s %s\n",
				list->name, entry->seq,
				community_direct_str(entry->direct),
				community_list_config_str(entry));
			write++;
		}
	for (list = cm->str.head; list; list = list->next)
		for (entry = list->head; entry; entry = entry->next) {
			vty_out(vty,
				"bgp community-list %s %s seq %" PRId64 " %s %s\n",
				entry->style == COMMUNITY_LIST_STANDARD
					? "standard"
					: "expanded",
				list->name, entry->seq,
				community_direct_str(entry->direct),
				community_list_config_str(entry));
			write++;
		}

	/* Extcommunity-list.  */
	cm = community_list_master_lookup(bgp_clist, EXTCOMMUNITY_LIST_MASTER);

	for (list = cm->num.head; list; list = list->next)
		for (entry = list->head; entry; entry = entry->next) {
			vty_out(vty,
				"bgp extcommunity-list %s seq %" PRId64 " %s %s\n",
				list->name, entry->seq,
				community_direct_str(entry->direct),
				community_list_config_str(entry));
			write++;
		}
	for (list = cm->str.head; list; list = list->next)
		for (entry = list->head; entry; entry = entry->next) {
			vty_out(vty,
				"bgp extcommunity-list %s %s seq %" PRId64" %s %s\n",
				entry->style == EXTCOMMUNITY_LIST_STANDARD
					? "standard"
					: "expanded",
				list->name, entry->seq,
				community_direct_str(entry->direct),
				community_list_config_str(entry));
			write++;
		}


	/* lcommunity-list.  */
	cm = community_list_master_lookup(bgp_clist,
					  LARGE_COMMUNITY_LIST_MASTER);

	for (list = cm->num.head; list; list = list->next)
		for (entry = list->head; entry; entry = entry->next) {
			vty_out(vty,
				"bgp large-community-list %s seq %" PRId64" %s %s\n",
				list->name, entry->seq,
				community_direct_str(entry->direct),
				community_list_config_str(entry));
			write++;
		}
	for (list = cm->str.head; list; list = list->next)
		for (entry = list->head; entry; entry = entry->next) {
			vty_out(vty,
				"bgp large-community-list %s %s seq %" PRId64" %s %s\n",

				entry->style == LARGE_COMMUNITY_LIST_STANDARD
					? "standard"
					: "expanded",
				list->name, entry->seq, community_direct_str(entry->direct),
				community_list_config_str(entry));
			write++;
		}

	return write;
}

static int community_list_config_write(struct vty *vty);
static struct cmd_node community_list_node = {
	.name = "community list",
	.node = COMMUNITY_LIST_NODE,
	.prompt = "",
	.config_write = community_list_config_write,
};

static void community_list_vty(void)
{
	install_node(&community_list_node);

	/* Community-list.  */
	install_element(CONFIG_NODE, &bgp_community_list_standard_cmd);
	install_element(CONFIG_NODE, &bgp_community_list_expanded_all_cmd);
	install_element(CONFIG_NODE, &no_bgp_community_list_standard_all_cmd);
	install_element(CONFIG_NODE, &no_bgp_community_list_standard_all_list_cmd);
	install_element(CONFIG_NODE, &no_bgp_community_list_expanded_all_cmd);
	install_element(CONFIG_NODE, &no_bgp_community_list_expanded_all_list_cmd);
	install_element(VIEW_NODE, &show_bgp_community_list_cmd);
	install_element(VIEW_NODE, &show_bgp_community_list_arg_cmd);

	/* Extcommunity-list.  */
	install_element(CONFIG_NODE, &bgp_extcommunity_list_standard_cmd);
	install_element(CONFIG_NODE, &bgp_extcommunity_list_name_expanded_cmd);
	install_element(CONFIG_NODE, &no_bgp_extcommunity_list_standard_all_cmd);
	install_element(CONFIG_NODE,
			&no_bgp_extcommunity_list_standard_all_list_cmd);
	install_element(CONFIG_NODE, &no_bgp_extcommunity_list_expanded_all_cmd);
	install_element(CONFIG_NODE,
			&no_bgp_extcommunity_list_expanded_all_list_cmd);
	install_element(VIEW_NODE, &show_bgp_extcommunity_list_cmd);
	install_element(VIEW_NODE, &show_bgp_extcommunity_list_arg_cmd);

	/* Large Community List */
	install_element(CONFIG_NODE, &bgp_lcommunity_list_standard_cmd);
	install_element(CONFIG_NODE, &bgp_lcommunity_list_expanded_cmd);
	install_element(CONFIG_NODE, &bgp_lcommunity_list_name_standard_cmd);
	install_element(CONFIG_NODE, &bgp_lcommunity_list_name_expanded_cmd);
	install_element(CONFIG_NODE, &no_bgp_lcommunity_list_all_cmd);
	install_element(CONFIG_NODE,
			&no_bgp_lcommunity_list_name_standard_all_cmd);
	install_element(CONFIG_NODE,
			&no_bgp_lcommunity_list_name_expanded_all_cmd);
	install_element(CONFIG_NODE, &no_bgp_lcommunity_list_standard_cmd);
	install_element(CONFIG_NODE, &no_bgp_lcommunity_list_expanded_cmd);
	install_element(CONFIG_NODE, &no_bgp_lcommunity_list_name_standard_cmd);
	install_element(CONFIG_NODE, &no_bgp_lcommunity_list_name_expanded_cmd);
	install_element(VIEW_NODE, &show_bgp_lcommunity_list_cmd);
	install_element(VIEW_NODE, &show_bgp_lcommunity_list_arg_cmd);

	bgp_community_list_command_completion_setup();
}

static struct cmd_node community_alias_node = {
	.name = "community alias",
	.node = COMMUNITY_ALIAS_NODE,
	.prompt = "",
	.config_write = bgp_community_alias_write,
};

void community_alias_vty(void)
{
	install_node(&community_alias_node);

	/* Community-list.  */
	install_element(CONFIG_NODE, &bgp_community_alias_cmd);

	bgp_community_alias_command_completion_setup();
}
