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
	struct listnode *node;
	sa_family_t peer_family;

	/*
	 * peer_by_addr is kept sorted by address, so walk it looking for the
	 * first entry strictly greater than the supplied key. This works even if
	 * the exact peer has disappeared between requests.
	 */
	for (ALL_LIST_ELEMENTS_RO(bgp->peer_by_addr, node, peer)) {
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
	struct listnode *node;
	struct listnode *head;

	if (family == AF_UNSPEC) {
		head = listhead(bgp->peer_by_addr);
		return head ? listgetdata(head) : NULL;
	}

	/*
	 * Iterate through the peers in the VRF and get the first peer
	 * that matches the address type.
	 */
	for (ALL_LIST_ELEMENTS_RO(bgp->peer_by_addr, node, peer)) {
		if (sockunion_family(&peer->connection->su) == family) {
			first_peer = peer;
			break;
		}
	}
	return first_peer;
}


static struct peer *bgp_snmp_get_next_peer_in_vrf(struct bgp *bgp, const struct ipaddr *addr,
						  sa_family_t peer_family)
{
	struct peer *peer;
	struct listnode *node;

	if (!addr)
		return NULL;

	for (ALL_LIST_ELEMENTS_RO(bgp->peer_by_addr, node, peer)) {
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

struct peer *bgp_snmp_get_first_peer(bool all_vrfs, sa_family_t family)
{
	struct bgp *bgp;
	struct peer *peer = NULL;

	if (all_vrfs) {
		/* Lookup in all VRFs */
		struct listnode *head = listhead(bm->bgp);

		bgp = head ? listgetdata(head) : NULL;
		if (bgp)
			peer = bgp_snmp_get_first_peer_in_vrf(bgp, family);

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
	bool next_vrf = false;

	if (all_vrfs) {
		/* Lookup in all VRFs */
		for (ALL_LIST_ELEMENTS_RO(bm->bgp, bgpnode, bgp)) {
			if (next_vrf) {
				peer = bgp_snmp_get_first_peer_in_vrf(bgp, family);
				if (peer)
					break;
			} else if (bgp->vrf_id == peer_vrf_id) {
				peer = bgp_snmp_get_next_peer_in_vrf(bgp, addr, family);
				if (!peer) {
					next_vrf = true;
					continue;
				} else {
					/* Found a peer in the current VRF */
					break;
				}
			}
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
