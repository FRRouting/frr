// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP4 SNMP support
 * Copyright (C) 1999, 2000 Kunihiro Ishiguro
 */

#include <zebra.h>

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include "if.h"
#include "log.h"
#include "prefix.h"
#include "command.h"
#include "frrevent.h"
#include "smux.h"
#include "filter.h"
#include "hook.h"
#include "libfrr.h"
#include "lib/version.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_snmp.h"
#include "bgpd/bgp_snmp_bgp4.h"
#include "bgpd/bgp_snmp_bgp4v2.h"
#include "bgpd/bgp_snmp_cbgp4.h"
#include "bgpd/bgp_mplsvpn_snmp.h"
#include "bgpd/bgp_snmp_clippy.c"



static int bgp_cli_snmp_traps_config_write(struct vty *vty);

DEFPY(bgp_snmp_traps_rfc4273, bgp_snmp_traps_rfc4273_cmd,
      "[no$no] bgp snmp traps rfc4273",
      NO_STR BGP_STR
      "Configure BGP SNMP\n"
      "Configure SNMP traps for BGP\n"
      "Configure use of rfc4273 SNMP traps for BGP\n")
{
	if (no) {
		UNSET_FLAG(bm->options, BGP_OPT_TRAPS_RFC4273);
		return CMD_SUCCESS;
	}
	SET_FLAG(bm->options, BGP_OPT_TRAPS_RFC4273);
	return CMD_SUCCESS;
}

DEFPY(bgp_snmp_traps_rfc4382, bgp_snmp_traps_rfc4382_cmd,
      "[no$no] bgp snmp traps rfc4382",
      NO_STR BGP_STR
      "Configure BGP SNMP\n"
      "Configure SNMP traps for BGP\n"
      "Configure use of rfc4382 SNMP traps for BGP\n")
{
	if (no) {
		UNSET_FLAG(bm->options, BGP_OPT_TRAPS_RFC4382);
		return CMD_SUCCESS;
	}
	SET_FLAG(bm->options, BGP_OPT_TRAPS_RFC4382);
	return CMD_SUCCESS;
}

DEFPY(bgp_snmp_traps_bgp4_mibv2, bgp_snmp_traps_bgp4_mibv2_cmd,
      "[no$no] bgp snmp traps bgp4-mibv2",
      NO_STR BGP_STR
      "Configure BGP SNMP\n"
      "Configure SNMP traps for BGP\n"
      "Configure use of BGP4-MIBv2 SNMP traps for BGP\n")
{
	if (no) {
		UNSET_FLAG(bm->options, BGP_OPT_TRAPS_BGP4MIBV2);
		return CMD_SUCCESS;
	}
	SET_FLAG(bm->options, BGP_OPT_TRAPS_BGP4MIBV2);
	return CMD_SUCCESS;
}

static void bgp_snmp_traps_init(void)
{
	install_element(CONFIG_NODE, &bgp_snmp_traps_rfc4273_cmd);
	install_element(CONFIG_NODE, &bgp_snmp_traps_bgp4_mibv2_cmd);
	install_element(CONFIG_NODE, &bgp_snmp_traps_rfc4382_cmd);

	SET_FLAG(bm->options, BGP_OPT_TRAPS_RFC4273);
	/* BGP4MIBv2 traps are disabled by default */

	SET_FLAG(bm->options, BGP_OPT_TRAPS_RFC4382);
}

int bgp_cli_snmp_traps_config_write(struct vty *vty)
{
	int write = 0;

	if (!CHECK_FLAG(bm->options, BGP_OPT_TRAPS_RFC4273)) {
		vty_out(vty, "no bgp snmp traps rfc4273\n");
		write++;
	}
	if (CHECK_FLAG(bm->options, BGP_OPT_TRAPS_BGP4MIBV2)) {
		vty_out(vty, "bgp snmp traps bgp4-mibv2\n");
		write++;
	}
	if (!CHECK_FLAG(bm->options, BGP_OPT_TRAPS_RFC4382)) {
		vty_out(vty, "no bgp snmp traps rfc4382\n");
		write++;
	}

	return write;
}

static int bgpTrapEstablished(struct peer *peer)
{
	if (CHECK_FLAG(bm->options, BGP_OPT_TRAPS_RFC4273))
		bgp4TrapEstablished(peer);

	if (CHECK_FLAG(bm->options, BGP_OPT_TRAPS_BGP4MIBV2))
		bgpv2TrapEstablished(peer);

	return 0;
}

static int bgpTrapBackwardTransition(struct peer *peer)
{
	if (CHECK_FLAG(bm->options, BGP_OPT_TRAPS_RFC4273))
		bgp4TrapBackwardTransition(peer);

	if (CHECK_FLAG(bm->options, BGP_OPT_TRAPS_BGP4MIBV2))
		bgpv2TrapBackwardTransition(peer);

	return 0;
}

static int bgp_snmp_init(struct event_loop *tm)
{
	smux_init(tm);
	bgp_snmp_traps_init();
	bgp_snmp_bgp4_init(tm);
	bgp_snmp_bgp4v2_init(tm);
	bgp_snmp_cbgp4_init(tm);
	bgp_mpls_l3vpn_module_init();
	return 0;
}

static int bgp_snmp_module_init(void)
{
	hook_register(peer_status_changed, bgpTrapEstablished);
	hook_register(peer_backward_transition, bgpTrapBackwardTransition);
	hook_register(frr_late_init, bgp_snmp_init);
	hook_register(bgp_snmp_traps_config_write,
		      bgp_cli_snmp_traps_config_write);
	return 0;
}

static struct peer *bgp_snmp_lookup_peer_in_vrf(struct bgp *bgp, const struct ipaddr *addr)
{
	struct peer *peer;
	sa_family_t peer_family;

	/*
	 * peer_by_addr is kept sorted by address, so walk it looking for the
	 * first entry strictly greater than the supplied key. This works even if
	 * the exact peer has disappeared between requests.
	 */
	frr_each (peer_by_addr_list, &bgp->peer_by_addr, peer) {
		peer_family = sockunion_family(&peer->connection->su);

		/* Check if the address matches */
		if (peer_family != addr->ipa_type)
			continue;

		switch (peer_family) {
		case AF_INET:
			if (IPV4_ADDR_SAME(&peer->connection->su.sin.sin_addr, &addr->ipaddr_v4))
				return peer;
			break;
		case AF_INET6:
			if (IPV6_ADDR_SAME(&peer->connection->su.sin6.sin6_addr, &addr->ipaddr_v6))
				return peer;
			break;
		default:
			break;
		}
	}

	return NULL;
}

static struct peer *bgp_snmp_get_first_peer_in_vrf(struct bgp *bgp, sa_family_t family)
{
	struct peer *peer;
	struct peer *first_peer = NULL;

	if (family == AF_UNSPEC)
		return peer_by_addr_list_first(&bgp->peer_by_addr);

	/*
	 * Iterate through the peers in the VRF and get the first peer
	 * that matches the address type.
	 */
	frr_each (peer_by_addr_list, &bgp->peer_by_addr, peer) {
		if (sockunion_family(&peer->connection->su) == family) {
			first_peer = peer;
			break;
		}
	}
	return first_peer;
}


/*
 * Static map of (AFI, SAFI) pairs in IANA lexicographic order.
 * This map must be kept in sync with IANA AFI/SAFI definitions.
 * See lib/iana_afi.h for IANA values.
 *
 * NOTE: When adding new AFI/SAFI to BGP, this map MUST be updated
 * to maintain correct SNMP OID ordering.
 */
static const struct {
	afi_t afi;
	safi_t safi;
} iana_ordered_afi_safi[] = {
	{ AFI_IP, SAFI_UNICAST },	   /* IANA 1.1 */
	{ AFI_IP, SAFI_MULTICAST },	   /* IANA 1.2 */
	{ AFI_IP, SAFI_LABELED_UNICAST },  /* IANA 1.4 */
	{ AFI_IP, SAFI_MPLS_VPN },	   /* IANA 1.128 */
	{ AFI_IP, SAFI_FLOWSPEC },	   /* IANA 1.133 */
	{ AFI_IP6, SAFI_UNICAST },	   /* IANA 2.1 */
	{ AFI_IP6, SAFI_MULTICAST },	   /* IANA 2.2 */
	{ AFI_IP6, SAFI_LABELED_UNICAST }, /* IANA 2.4 */
	{ AFI_IP6, SAFI_MPLS_VPN },	   /* IANA 2.128 */
	{ AFI_IP6, SAFI_FLOWSPEC },	   /* IANA 2.133 */
	{ AFI_L2VPN, SAFI_EVPN },	   /* IANA 25.70 */
};

/*
 * Get the next peer address family in lexicographic IANA (AFI, SAFI) order.
 * This ensures SNMP OIDs are returned in strictly increasing order.
 *
 * @param peer - The peer to search
 * @param afi - Current AFI (AFI_UNSPEC to start from beginning)
 * @param safi - Current SAFI (SAFI_UNSPEC to start from beginning)
 * @return Next peer_af structure, or NULL if no more address families
 */
struct peer_af *bgp_snmp_peer_af_next(struct peer *peer, afi_t afi, safi_t safi)
{
	size_t start_idx = 0;
	int afid;

	if (!peer)
		return NULL;

	/* Find starting position in IANA-ordered map */
	if (afi != AFI_UNSPEC && safi != SAFI_UNSPEC) {
		for (size_t i = 0; i < array_size(iana_ordered_afi_safi); i++) {
			if (iana_ordered_afi_safi[i].afi == afi &&
			    iana_ordered_afi_safi[i].safi == safi) {
				start_idx = i + 1;
				break;
			}
		}
	}

	/* Iterate through map in IANA order, return first active AF */
	for (size_t i = start_idx; i < array_size(iana_ordered_afi_safi); i++) {
		afid = afindex(iana_ordered_afi_safi[i].afi, iana_ordered_afi_safi[i].safi);
		if (afid < BGP_AF_MAX && peer->peer_af_array[afid])
			return peer->peer_af_array[afid];
	}

	return NULL;
}

static struct peer *bgp_snmp_get_next_peer_in_vrf(struct bgp *bgp, const struct ipaddr *addr,
						  sa_family_t peer_family)
{
	struct peer *peer;

	if (!addr)
		return NULL;

	frr_each (peer_by_addr_list, &bgp->peer_by_addr, peer) {
		sa_family_t fam;
		struct ipaddr peer_addr;

		fam = sockunion_family(&peer->connection->su);

		if (peer_family != AF_UNSPEC && fam != peer_family)
			continue;

		switch (fam) {
		case AF_INET:
			peer_addr.ipa_type = IPADDR_V4;
			peer_addr.ipaddr_v4 = peer->connection->su.sin.sin_addr;
			break;
		case AF_INET6:
			peer_addr.ipa_type = IPADDR_V6;
			peer_addr.ipaddr_v6 = peer->connection->su.sin6.sin6_addr;
			break;
		default:
			continue;
		}

		if (ipaddr_cmp(&peer_addr, addr) > 0)
			return peer;
	}

	return NULL;
}

struct peer *bgp_snmp_lookup_peer(vrf_id_t peer_vrf_id, const struct ipaddr *addr)
{
	struct bgp *bgp;
	struct peer *peer = NULL;

	if (!addr)
		return NULL;
	bgp = bgp_lookup_by_vrf_id(peer_vrf_id);

	if (bgp) {
		/* Lookup in VRF */
		peer = bgp_snmp_lookup_peer_in_vrf(bgp, addr);
	}
	return peer;
}

/*
 * Find the next VRF with lowest VRF ID > min_vrf_id.
 * Pass min_vrf_id = VRF_UNKNOWN to find the first VRF with lowest ID.
 * Returns the BGP instance, or NULL if no next VRF is found.
 * Note: Caller should check if the returned VRF has peers of the desired family.
 */
static struct bgp *bgp_snmp_get_next_vrf(vrf_id_t min_vrf_id)
{
	struct bgp *bgp;
	struct bgp *bgp_next = NULL;
	struct listnode *bgpnode;
	vrf_id_t next_vrf_id = VRF_UNKNOWN;
	bool find_first = (min_vrf_id == VRF_UNKNOWN);

	/* Find VRF with lowest VRF ID (> min_vrf_id if not finding first) */
	for (ALL_LIST_ELEMENTS_RO(bm->bgp, bgpnode, bgp)) {
		/* Skip VRF_UNKNOWN to prevent wrap-around in SNMP walks */
		if (bgp->vrf_id == VRF_UNKNOWN)
			continue;

		if (find_first || bgp->vrf_id > min_vrf_id) {
			if (bgp_next == NULL || bgp->vrf_id < next_vrf_id) {
				bgp_next = bgp;
				next_vrf_id = bgp->vrf_id;
			}
		}
	}

	return bgp_next;
}

struct peer *bgp_snmp_get_first_peer(bool all_vrfs, sa_family_t family)
{
	struct bgp *bgp;
	struct peer *peer = NULL;
	vrf_id_t vrf_id;

	if (all_vrfs) {
		/* Find VRF with lowest VRF ID that has peers */
		vrf_id = VRF_UNKNOWN;
		while ((bgp = bgp_snmp_get_next_vrf(vrf_id)) != NULL) {
			peer = bgp_snmp_get_first_peer_in_vrf(bgp, family);
			if (peer)
				break;
			vrf_id = bgp->vrf_id;
		}

	} else {
		/* Lookup in default VRF */
		bgp = bgp_get_default();
		if (bgp)
			peer = bgp_snmp_get_first_peer_in_vrf(bgp, family);
	}
	return peer;
}

struct peer *bgp_snmp_get_next_peer(bool all_vrfs, vrf_id_t peer_vrf_id, sa_family_t family,
				    const struct ipaddr *addr)
{
	struct bgp *bgp;
	struct peer *peer = NULL;
	struct listnode *bgpnode;
	vrf_id_t vrf_id;

	if (all_vrfs) {
		/* First try to find next peer in current VRF */
		for (ALL_LIST_ELEMENTS_RO(bm->bgp, bgpnode, bgp)) {
			if (bgp->vrf_id == peer_vrf_id) {
				peer = bgp_snmp_get_next_peer_in_vrf(bgp, addr, family);
				if (peer)
					return peer;
				break;
			}
		}

		/* No more peers in current VRF, find next VRF with lowest ID > peer_vrf_id */
		vrf_id = peer_vrf_id;
		while ((bgp = bgp_snmp_get_next_vrf(vrf_id)) != NULL) {
			peer = bgp_snmp_get_first_peer_in_vrf(bgp, family);
			if (peer)
				break;
			vrf_id = bgp->vrf_id;
		}

	} else {
		/* Lookup in default VRF */
		bgp = bgp_get_default();
		if (bgp)
			peer = bgp_snmp_get_next_peer_in_vrf(bgp, addr, family);
	}
	return peer;
}

FRR_MODULE_SETUP(.name = "bgpd_snmp", .version = FRR_VERSION,
		 .description = "bgpd AgentX SNMP module",
		 .init = bgp_snmp_module_init,
);
