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
#include "bgpd/bgp_mplsvpn_snmp.h"

static void bgp_snmp_traps_init(void)
{
	/*
	 * Trap CLI lives in bgp_cli.c (YANG /frr-bgp:bgp-daemon/snmp-traps).
	 * Seed runtime defaults to match YANG defaults when the SNMP module
	 * loads (before any explicit config is applied).
	 */
	SET_FLAG(bm->options, BGP_OPT_TRAPS_RFC4273);
	/* BGP4MIBv2 traps are disabled by default */
	SET_FLAG(bm->options, BGP_OPT_TRAPS_RFC4382);
}

int bgpTrapEstablished(struct peer_connection *connection)
{
	struct peer *peer = connection->peer;

	if (CHECK_FLAG(bm->options, BGP_OPT_TRAPS_RFC4273))
		bgp4TrapEstablished(peer);

	if (CHECK_FLAG(bm->options, BGP_OPT_TRAPS_BGP4MIBV2))
		bgpv2TrapEstablished(peer);

	return 0;
}

int bgpTrapBackwardTransition(struct peer *peer)
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
	bgp_mpls_l3vpn_module_init();
	return 0;
}

static int bgp_snmp_terminate(void)
{
	smux_terminate();
	return 0;
}

static int bgp_snmp_module_init(void)
{
	hook_register(peer_status_changed, bgpTrapEstablished);
	hook_register(peer_backward_transition, bgpTrapBackwardTransition);
	hook_register(frr_late_init, bgp_snmp_init);
	hook_register(frr_fini, bgp_snmp_terminate);
	return 0;
}

FRR_MODULE_SETUP(.name = "bgpd_snmp", .version = FRR_VERSION,
		 .description = "bgpd AgentX SNMP module",
		 .init = bgp_snmp_module_init,
);
