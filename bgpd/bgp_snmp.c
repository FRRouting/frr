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
#include "bgpd/bgp_snmp_clippy.c"

uint32_t bgp_snmp_traps_flags;

static int bgp_cli_snmp_traps_config_write(struct vty *vty);

DEFPY(bgp_snmp_traps_rfc4273, bgp_snmp_traps_rfc4273_cmd,
      "bgp snmp traps rfc4273 <enable$on|disable$off>",
      BGP_STR "Configure BGP SNMP\n"
	      "Configure SNMP traps for BGP \n"
	      "Configure use of rfc4273 SNMP traps for BGP \n"
	      "Enable rfc4273 traps\n"
	      "Disable rfc4273 traps\n")
{
	if (on) {
		SET_FLAG(bgp_snmp_traps_flags, BGP_SNMP_TRAPS_RFC4273_ENABLED);
		return CMD_SUCCESS;
	}
	UNSET_FLAG(bgp_snmp_traps_flags, BGP_SNMP_TRAPS_RFC4273_ENABLED);
	return CMD_SUCCESS;
}

static void bgp_snmp_traps_init(void)
{
	install_element(CONFIG_NODE, &bgp_snmp_traps_rfc4273_cmd);
	SET_FLAG(bgp_snmp_traps_flags, BGP_SNMP_TRAPS_RFC4273_ENABLED);
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

	return write;
}

int bgpTrapEstablished(struct peer *peer)
{
	bgp4TrapEstablished(peer);
	bgpv2TrapEstablished(peer);
	return 0;
}

int bgpTrapBackwardTransition(struct peer *peer)
{
	bgp4TrapBackwardTransition(peer);
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

static int bgp_snmp_module_init(void)
{
	hook_register(peer_status_changed, bgpTrapEstablished);
	hook_register(peer_backward_transition, bgpTrapBackwardTransition);
	hook_register(frr_late_init, bgp_snmp_init);
	hook_register(bgp_snmp_traps_config_write,
		      bgp_cli_snmp_traps_config_write);
	return 0;
}

FRR_MODULE_SETUP(.name = "bgpd_snmp", .version = FRR_VERSION,
		 .description = "bgpd AgentX SNMP module",
		 .init = bgp_snmp_module_init,
);
