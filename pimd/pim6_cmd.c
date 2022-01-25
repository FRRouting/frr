/*
 * PIM for IPv6 FRR
 * Copyright (C) 2022  Vmware, Inc.
 *		       Mobashshera Rasool <mrasool@vmware.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "lib/json.h"
#include "command.h"
#include "if.h"
#include "prefix.h"
#include "zclient.h"
#include "plist.h"
#include "hash.h"
#include "nexthop.h"
#include "vrf.h"
#include "ferr.h"

#include "pimd.h"
#include "pim6_cmd.h"
#include "pim_vty.h"
#include "lib/northbound_cli.h"
#include "pim_errors.h"
#include "pim_nb.h"

#ifndef VTYSH_EXTRACT_PL
#include "pimd/pim6_cmd_clippy.c"
#endif

DEFPY (ipv6_pim_rp,
       ipv6_pim_rp_cmd,
       "ipv6 pim rp X:X::X:X$rp [X:X::X:X/M]$group",
       IPV6_STR
       PIM_STR
       "Rendevous Point\n"
       "ipv6 address of RP\n"
       "Group Address range to cover\n")
{
	const char *vrfname;
	char rp_group_xpath[XPATH_MAXLEN];

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname == NULL)
		return CMD_WARNING_CONFIG_FAILED;

	snprintf(rp_group_xpath, sizeof(rp_group_xpath),
		 FRR_PIM_STATIC_RP_XPATH,
		 "frr-pim:pimd", "pim", vrfname, "frr-routing:ipv6",
		 rp_str);
	strlcat(rp_group_xpath, "/group-list", sizeof(rp_group_xpath));

	if (!group_str)
		nb_cli_enqueue_change(vty, rp_group_xpath, NB_OP_CREATE,
				"FF00::0/8");
	else
		nb_cli_enqueue_change(vty, rp_group_xpath, NB_OP_CREATE,
				group_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY (no_ipv6_pim_rp,
       no_ipv6_pim_rp_cmd,
       "no ipv6 pim rp X:X::X:X$rp [X:X::X:X/M]$group",
       NO_STR
       IPV6_STR
       PIM_STR
       "Rendevous Point\n"
       "ipv6 address of RP\n"
       "Group Address range to cover\n")
{
	char group_list_xpath[XPATH_MAXLEN + 32];
	char group_xpath[XPATH_MAXLEN + 64];
	char rp_xpath[XPATH_MAXLEN];
	const char *vrfname;
	const struct lyd_node *group_dnode;
	const char *grp_def = "FF00::0/8";

	if (!group_str)
		group_str = grp_def;

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname == NULL)
		return CMD_WARNING_CONFIG_FAILED;

	snprintf(rp_xpath, sizeof(rp_xpath), FRR_PIM_STATIC_RP_XPATH,
		 "frr-pim:pimd", "pim", vrfname, "frr-routing:ipv6",
		 rp_str);

	snprintf(group_list_xpath, sizeof(group_list_xpath), "%s/group-list",
		 rp_xpath);

	snprintf(group_xpath, sizeof(group_xpath), "%s[.='%s']",
		 group_list_xpath, group_str);

	if (!yang_dnode_exists(vty->candidate_config->dnode, group_xpath)) {
		vty_out(vty, "%% Unable to find specified RP\n");
		return NB_OK;
	}

	group_dnode = yang_dnode_get(vty->candidate_config->dnode, group_xpath);

	if (yang_is_last_list_dnode(group_dnode))
		nb_cli_enqueue_change(vty, rp_xpath, NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, group_list_xpath, NB_OP_DESTROY,
				      group_str);

	return nb_cli_apply_changes(vty, NULL);
}

void pim_cmd_init(void)
{
	if_cmd_init(pim_interface_config_write);

	install_element(CONFIG_NODE, &ipv6_pim_rp_cmd);
	install_element(VRF_NODE, &ipv6_pim_rp_cmd);
	install_element(CONFIG_NODE, &no_ipv6_pim_rp_cmd);
	install_element(VRF_NODE, &no_ipv6_pim_rp_cmd);
}
