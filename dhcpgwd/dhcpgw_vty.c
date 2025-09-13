// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * DHCPGWd - vty header
 * Copyright (C) 2025 VyOS Inc.
 * Kyrylo Yatsenko
 */
#include <zebra.h>

#include "lib/log.h"

#include "command.h"
#include "vty.h"
#include "vrf.h"
#include "mgmt_be_client.h"
#include "mpls.h"

#include "dhcpgw_vty.h"
#include "dhcpgw_debug.h"
#include "dhcpgwd/dhcpgw_vty_clippy.c"

#include "dhcpgwd/dhcpgw_routes.h"

#define DHCPGWD_STR "Dhcpgw route daemon\n"
/* Seems clippy cannot use macro from header?.. Had to repeat here */
#define DHCP_GATEWAY_CMD_STR "dhcp-gateway"

/** We use command itself to replace 'dhcp-gateway' and send to staticd */
struct dhcpgw_route_args {
	/** "no" command? */
	bool no;

	int af;
	const char *ifname;

	int argc;
	struct cmd_token **argv;
};

static int dhcpgw_route_run(struct vty *vty, struct dhcpgw_route_args *args)
{
	int dhcpgw_index = 0;

	if (!argv_find(args->argv, args->argc, DHCP_GATEWAY_CMD_STR, &dhcpgw_index)) {
		zlog_err("Unexpected command in %s! " DHCP_GATEWAY_CMD_STR
			 " should have been found!",
			 __func__);
		return 1;
	}
	char *prefix = argv_concat(args->argv, dhcpgw_index, args->no ? 1 : 0);
	char *suffix = argv_concat(args->argv, args->argc, dhcpgw_index + 1);

	dhcpgw_routes_process(args->no, args->ifname, args->af, prefix, suffix);

	XFREE(MTYPE_TMP, prefix);
	XFREE(MTYPE_TMP, suffix);
	return 0;
}

DEFPY(debug_dhcpgwd, debug_dhcpgwd_cmd,
	   "[no] debug dhcpgw",
	   NO_STR DEBUG_STR DHCPGWD_STR
	   )
{
	dhcpgw_debug_set(vty->node, !no);

	return CMD_SUCCESS;
}

DEFUN_NOSH (show_debugging_dhcpgw,
	    show_debugging_dhcpgw_cmd,
	    "show debugging [dhcpgw]",
	    SHOW_STR
	    DEBUG_STR
	    "DhcpgwInformation\n")
{
	vty_out(vty, "Dhcpgwd debugging status\n");

	cmd_show_lib_debugs(vty);

	return CMD_SUCCESS;
}

/* Copy-paste from staticd. We'll be sending the command
 * to staticd so it is important to synchronise the commands.
 * TODO: do this in some automatic manner, at least check...
 */
DEFPY(ip_route_dhcpgw_interface,
      ip_route_dhcpgw_interface_cmd,
      "[no] ip route\
	<A.B.C.D/M$prefix|A.B.C.D$prefix A.B.C.D$mask> \
	" DHCP_GATEWAY_CMD_STR "                       \
	INTERFACE$ifname                               \
	[{                                             \
	  tag (1-4294967295)                           \
	  |(1-255)$distance                            \
	  |vrf NAME                                    \
	  |label WORD                                  \
	  |table (1-4294967295)                        \
	  |nexthop-vrf NAME                            \
	  |onlink$onlink                               \
	  |color (1-4294967295)                        \
	  |bfd$bfd [{multi-hop$bfd_multi_hop|source A.B.C.D$bfd_source|profile BFDPROF$bfd_profile}] \
          }]",
      NO_STR IP_STR
      "Establish static routes\n"
      "IP destination prefix (e.g. 10.0.0.0/8)\n"
      "IP destination prefix\n"
      "IP destination prefix mask\n"
      "DHCP gateway\n"
      "IP gateway interface name\n"
      "Set tag for this route\n"
      "Tag value\n"
      "Distance value for this route\n"
      VRF_CMD_HELP_STR
      MPLS_LABEL_HELPSTR
      "Table to configure\n"
      "The table number to configure\n"
      VRF_CMD_HELP_STR
      "Treat the nexthop as directly attached to the interface\n"
      "SR-TE color\n"
      "The SR-TE color to configure\n"
      BFD_INTEGRATION_STR
      BFD_INTEGRATION_MULTI_HOP_STR
      BFD_INTEGRATION_SOURCE_STR
      BFD_INTEGRATION_SOURCEV4_STR
      BFD_PROFILE_STR
      BFD_PROFILE_NAME_STR)
{
	struct dhcpgw_route_args args = {
		.no = !!no,
		.ifname = ifname,
		.af = AF_INET,
		.argc = argc,
		.argv = argv,
	};

	dhcpgw_route_run(vty, &args);
	return CMD_SUCCESS;
}

DEFPY(dhcpgw_update,
      dhcpgw_update_cmd,
      "dhcpgw update INTERFACE$ifname",
      DHCPGWD_STR
      "Update gateway IP(s)\n"
      "Specific interface to update IP of\n"
      )
{
	dhcpgw_routes_update_interface(ifname);
	return CMD_SUCCESS;
}

DEFPY(dhcpgw_show_route,
      dhcpgw_show_route_cmd,
      "show dhcpgw route",
      SHOW_STR
      DHCPGWD_STR
      "DHCP gateway routes\n"
      )
{
	do_show_dhcpgw_routes(vty);
	return CMD_SUCCESS;
}

void dhcpgw_vty_init(void)
{
#ifndef INCLUDE_MGMTD_CMDDEFS_ONLY
	install_element(CONFIG_NODE, &ip_route_dhcpgw_interface_cmd);
	install_element(ENABLE_NODE, &debug_dhcpgwd_cmd);
	install_element(CONFIG_NODE, &debug_dhcpgwd_cmd);
	install_element(ENABLE_NODE, &show_debugging_dhcpgw_cmd);

	install_element(ENABLE_NODE, &dhcpgw_update_cmd);
	install_element(ENABLE_NODE, &dhcpgw_show_route_cmd);

	mgmt_be_client_lib_vty_init();
#endif
}
