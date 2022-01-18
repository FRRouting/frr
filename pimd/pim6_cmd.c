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
#include "pim_cmd_common.h"

#ifndef VTYSH_EXTRACT_PL
#include "pimd/pim6_cmd_clippy.c"
#endif

DEFPY (ipv6_pim_joinprune_time,
       ipv6_pim_joinprune_time_cmd,
       "ipv6 pim join-prune-interval (1-65535)$jpi",
       IPV6_STR
       PIM_STR
       "Join Prune Send Interval\n"
       "Seconds\n")
{
	return pim_process_join_prune_cmd(vty, jpi_str);
}

DEFPY (no_ipv6_pim_joinprune_time,
       no_ipv6_pim_joinprune_time_cmd,
       "no ipv6 pim join-prune-interval [(1-65535)]",
       NO_STR
       IPV6_STR
       PIM_STR
       "Join Prune Send Interval\n"
       IGNORED_IN_NO_STR)
{
	return pim_process_no_join_prune_cmd(vty);
}

DEFPY (ipv6_pim_spt_switchover_infinity,
       ipv6_pim_spt_switchover_infinity_cmd,
       "ipv6 pim spt-switchover infinity-and-beyond",
       IPV6_STR
       PIM_STR
       "SPT-Switchover\n"
       "Never switch to SPT Tree\n")
{
	return pim_process_spt_switchover_infinity_cmd(vty);
}

DEFPY (ipv6_pim_spt_switchover_infinity_plist,
       ipv6_pim_spt_switchover_infinity_plist_cmd,
       "ipv6 pim spt-switchover infinity-and-beyond prefix-list WORD$plist",
       IPV6_STR
       PIM_STR
       "SPT-Switchover\n"
       "Never switch to SPT Tree\n"
       "Prefix-List to control which groups to switch\n"
       "Prefix-List name\n")
{
	return pim_process_spt_switchover_prefixlist_cmd(vty, plist);
}

DEFPY (no_ipv6_pim_spt_switchover_infinity,
       no_ipv6_pim_spt_switchover_infinity_cmd,
       "no ipv6 pim spt-switchover infinity-and-beyond",
       NO_STR
       IPV6_STR
       PIM_STR
       "SPT_Switchover\n"
       "Never switch to SPT Tree\n")
{
	return pim_process_no_spt_switchover_cmd(vty);
}

DEFPY (no_ipv6_pim_spt_switchover_infinity_plist,
       no_ipv6_pim_spt_switchover_infinity_plist_cmd,
       "no ipv6 pim spt-switchover infinity-and-beyond prefix-list WORD",
       NO_STR
       IPV6_STR
       PIM_STR
       "SPT_Switchover\n"
       "Never switch to SPT Tree\n"
       "Prefix-List to control which groups to switch\n"
       "Prefix-List name\n")
{
	return pim_process_no_spt_switchover_cmd(vty);
}

DEFPY (ipv6_pim_packets,
       ipv6_pim_packets_cmd,
       "ipv6 pim packets (1-255)",
       IPV6_STR
       PIM_STR
       "packets to process at one time per fd\n"
       "Number of packets\n")
{
	return pim_process_pim_packet_cmd(vty, packets_str);
}

DEFPY (no_ipv6_pim_packets,
       no_ipv6_pim_packets_cmd,
       "no ipv6 pim packets [(1-255)]",
       NO_STR
       IPV6_STR
       PIM_STR
       "packets to process at one time per fd\n"
       IGNORED_IN_NO_STR)
{
	return pim_process_no_pim_packet_cmd(vty);
}

DEFPY (ipv6_pim_keep_alive,
       ipv6_pim_keep_alive_cmd,
       "ipv6 pim keep-alive-timer (1-65535)$kat",
       IPV6_STR
       PIM_STR
       "Keep alive Timer\n"
       "Seconds\n")
{
	return pim_process_keepalivetimer_cmd(vty, kat_str);
}

DEFPY (no_ipv6_pim_keep_alive,
       no_ipv6_pim_keep_alive_cmd,
       "no ipv6 pim keep-alive-timer [(1-65535)]",
       NO_STR
       IPV6_STR
       PIM_STR
       "Keep alive Timer\n"
       IGNORED_IN_NO_STR)
{
	return pim_process_no_keepalivetimer_cmd(vty);
}

DEFPY (ipv6_pim_rp_keep_alive,
       ipv6_pim_rp_keep_alive_cmd,
       "ipv6 pim rp keep-alive-timer (1-65535)$kat",
       IPV6_STR
       PIM_STR
       "Rendevous Point\n"
       "Keep alive Timer\n"
       "Seconds\n")
{
	return pim_process_rp_kat_cmd(vty, kat_str);
}

DEFPY (no_ipv6_pim_rp_keep_alive,
       no_ipv6_pim_rp_keep_alive_cmd,
       "no ipv6 pim rp keep-alive-timer [(1-65535)]",
       NO_STR
       IPV6_STR
       PIM_STR
       "Rendevous Point\n"
       "Keep alive Timer\n"
       IGNORED_IN_NO_STR)
{
	return pim_process_no_rp_kat_cmd(vty);
}

DEFPY (ipv6_pim_register_suppress,
       ipv6_pim_register_suppress_cmd,
       "ipv6 pim register-suppress-time (1-65535)$rst",
       IPV6_STR
       PIM_STR
       "Register Suppress Timer\n"
       "Seconds\n")
{
	return pim_process_register_suppress_cmd(vty, rst_str);
}

DEFPY (no_ipv6_pim_register_suppress,
       no_ipv6_pim_register_suppress_cmd,
       "no ipv6 pim register-suppress-time [(1-65535)]",
       NO_STR
       IPV6_STR
       PIM_STR
       "Register Suppress Timer\n"
       IGNORED_IN_NO_STR)
{
	return pim_process_no_register_suppress_cmd(vty);
}

DEFPY (interface_ipv6_pim,
       interface_ipv6_pim_cmd,
       "ipv6 pim",
       IPV6_STR
       PIM_STR)
{
	return pim_process_ip_pim_cmd(vty);
}

DEFPY (interface_no_ipv6_pim,
       interface_no_ipv6_pim_cmd,
       "no ipv6 pim",
       NO_STR
       IPV6_STR
       PIM_STR)
{
	return pim_process_no_ip_pim_cmd(vty);
}

DEFPY (interface_ipv6_pim_drprio,
       interface_ipv6_pim_drprio_cmd,
       "ipv6 pim drpriority (1-4294967295)",
       IPV6_STR
       PIM_STR
       "Set the Designated Router Election Priority\n"
       "Value of the new DR Priority\n")
{
	return pim_process_ip_pim_drprio_cmd(vty, drpriority_str);
}

DEFPY (interface_no_ipv6_pim_drprio,
       interface_no_ipv6_pim_drprio_cmd,
       "no ip pim drpriority [(1-4294967295)]",
       NO_STR
       IPV6_STR
       PIM_STR
       "Revert the Designated Router Priority to default\n"
       "Old Value of the Priority\n")
{
	return pim_process_no_ip_pim_drprio_cmd(vty);
}

DEFPY (interface_ipv6_pim_hello,
       interface_ipv6_pim_hello_cmd,
       "ipv6 pim hello (1-65535) [(1-65535)]$hold",
       IPV6_STR
       PIM_STR
       IFACE_PIM_HELLO_STR
       IFACE_PIM_HELLO_TIME_STR
       IFACE_PIM_HELLO_HOLD_STR)
{
	return pim_process_ip_pim_hello_cmd(vty, hello_str, hold_str);
}

DEFPY (interface_no_ipv6_pim_hello,
       interface_no_ipv6_pim_hello_cmd,
       "no ipv6 pim hello [(1-65535) [(1-65535)]]",
       NO_STR
       IPV6_STR
       PIM_STR
       IFACE_PIM_HELLO_STR
       IGNORED_IN_NO_STR
       IGNORED_IN_NO_STR)
{
	return pim_process_no_ip_pim_hello_cmd(vty);
}

DEFPY (interface_ipv6_pim_activeactive,
       interface_ipv6_pim_activeactive_cmd,
       "[no] ipv6 pim active-active",
       NO_STR
       IPV6_STR
       PIM_STR
       "Mark interface as Active-Active for MLAG operations\n")
{
	return pim_process_ip_pim_activeactive_cmd(vty, no);
}

DEFPY_HIDDEN (interface_ipv6_pim_ssm,
              interface_ipv6_pim_ssm_cmd,
              "ipv6 pim ssm",
              IPV6_STR
              PIM_STR
              IFACE_PIM_STR)
{
	int ret;

	ret = pim_process_ip_pim_cmd(vty);

	if (ret != NB_OK)
		return ret;

	vty_out(vty,
		"Enabled PIM SM on interface; configure PIM SSM range if needed\n");

	return NB_OK;
}

DEFPY_HIDDEN (interface_no_ipv6_pim_ssm,
              interface_no_ipv6_pim_ssm_cmd,
              "no ipv6 pim ssm",
              NO_STR
              IPV6_STR
              PIM_STR
              IFACE_PIM_STR)
{
	return pim_process_no_ip_pim_cmd(vty);
}

DEFPY_HIDDEN (interface_ipv6_pim_sm,
	      interface_ipv6_pim_sm_cmd,
	      "ipv6 pim sm",
	      IPV6_STR
	      PIM_STR
	      IFACE_PIM_SM_STR)
{
	return pim_process_ip_pim_cmd(vty);
}

DEFPY_HIDDEN (interface_no_ipv6_pim_sm,
	      interface_no_ipv6_pim_sm_cmd,
	      "no ipv6 pim sm",
	      NO_STR
	      IPV6_STR
	      PIM_STR
	      IFACE_PIM_SM_STR)
{
	return pim_process_no_ip_pim_cmd(vty);
}

/* boundaries */
DEFPY (interface_ipv6_pim_boundary_oil,
      interface_ipv6_pim_boundary_oil_cmd,
      "ipv6 multicast boundary oil WORD",
      IPV6_STR
      "Generic multicast configuration options\n"
      "Define multicast boundary\n"
      "Filter OIL by group using prefix list\n"
      "Prefix list to filter OIL with\n")
{
	return pim_process_ip_pim_boundary_oil_cmd(vty, oil);
}

DEFPY (interface_no_ipv6_pim_boundary_oil,
      interface_no_ipv6_pim_boundary_oil_cmd,
      "no ipv6 multicast boundary oil [WORD]",
      NO_STR
      IPV6_STR
      "Generic multicast configuration options\n"
      "Define multicast boundary\n"
      "Filter OIL by group using prefix list\n"
      "Prefix list to filter OIL with\n")
{
	return pim_process_no_ip_pim_boundary_oil_cmd(vty);
}

DEFPY (interface_ipv6_mroute,
       interface_ipv6_mroute_cmd,
       "ipv6 mroute INTERFACE X:X::X:X$group [X:X::X:X]$source",
       IPV6_STR
       "Add multicast route\n"
       "Outgoing interface name\n"
       "Group address\n"
       "Source address\n")
{
	return pim_process_ip_mroute_cmd(vty, interface, group_str, source_str);
}

DEFPY (interface_no_ipv6_mroute,
       interface_no_ipv6_mroute_cmd,
       "no ipv6 mroute INTERFACE X:X::X:X$group [X:X::X:X]$source",
       NO_STR
       IPV6_STR
       "Add multicast route\n"
       "Outgoing interface name\n"
       "Group Address\n"
       "Source Address\n")
{
	return pim_process_no_ip_mroute_cmd(vty, interface, group_str,
					    source_str);
}

DEFPY (ipv6_pim_rp,
       ipv6_pim_rp_cmd,
       "ipv6 pim rp X:X::X:X$rp [X:X::X:X/M]$gp",
       IPV6_STR
       PIM_STR
       "Rendezvous Point\n"
       "ipv6 address of RP\n"
       "Group Address range to cover\n")
{
	const char *group_str = (gp_str) ? gp_str : "FF00::0/8";

	return pim_process_rp_cmd(vty, rp_str, group_str);
}

DEFPY (no_ipv6_pim_rp,
       no_ipv6_pim_rp_cmd,
       "no ipv6 pim rp X:X::X:X$rp [X:X::X:X/M]$gp",
       NO_STR
       IPV6_STR
       PIM_STR
       "Rendezvous Point\n"
       "ipv6 address of RP\n"
       "Group Address range to cover\n")
{
	const char *group_str = (gp_str) ? gp_str : "FF00::0/8";

	return pim_process_no_rp_cmd(vty, rp_str, group_str);
}

DEFPY (ipv6_pim_rp_prefix_list,
       ipv6_pim_rp_prefix_list_cmd,
       "ipv6 pim rp X:X::X:X$rp prefix-list WORD$plist",
       IPV6_STR
       PIM_STR
       "Rendezvous Point\n"
       "ipv6 address of RP\n"
       "group prefix-list filter\n"
       "Name of a prefix-list\n")
{
	return pim_process_rp_plist_cmd(vty, rp_str, plist);
}

DEFPY (no_ipv6_pim_rp_prefix_list,
       no_ipv6_pim_rp_prefix_list_cmd,
       "no ipv6 pim rp X:X::X:X$rp prefix-list WORD$plist",
       NO_STR
       IPV6_STR
       PIM_STR
       "Rendezvous Point\n"
       "ipv6 address of RP\n"
       "group prefix-list filter\n"
       "Name of a prefix-list\n")
{
	return pim_process_no_rp_plist_cmd(vty, rp_str, plist);
}

DEFPY (interface_ipv6_mld_join,
       interface_ipv6_mld_join_cmd,
       "ipv6 mld join X:X::X:X$group [X:X::X:X$source]",
       IPV6_STR
       IFACE_MLD_STR
       "MLD join multicast group\n"
       "Multicast group address\n"
       "Source address\n")
{
	char xpath[XPATH_MAXLEN];

	if (source_str) {
		if (IPV6_ADDR_SAME(&source, &in6addr_any)) {
			vty_out(vty, "Bad source address %s\n", source_str);
			return CMD_WARNING_CONFIG_FAILED;
		}
	} else
		source_str = "::";

	snprintf(xpath, sizeof(xpath), FRR_GMP_JOIN_XPATH, "frr-routing:ipv6",
		 group_str, source_str);

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY (interface_no_ipv6_mld_join,
       interface_no_ipv6_mld_join_cmd,
       "no ipv6 mld join X:X::X:X$group [X:X::X:X$source]",
       NO_STR
       IPV6_STR
       IFACE_MLD_STR
       "MLD join multicast group\n"
       "Multicast group address\n"
       "Source address\n")
{
	char xpath[XPATH_MAXLEN];

	if (source_str) {
		if (IPV6_ADDR_SAME(&source, &in6addr_any)) {
			vty_out(vty, "Bad source address %s\n", source_str);
			return CMD_WARNING_CONFIG_FAILED;
		}
	} else
		source_str = "::";

	snprintf(xpath, sizeof(xpath), FRR_GMP_JOIN_XPATH, "frr-routing:ipv6",
		 group_str, source_str);

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY (interface_ipv6_mld,
       interface_ipv6_mld_cmd,
       "ipv6 mld",
       IPV6_STR
       IFACE_MLD_STR)
{
	nb_cli_enqueue_change(vty, "./enable", NB_OP_MODIFY, "true");

	return nb_cli_apply_changes(vty, FRR_GMP_INTERFACE_XPATH,
				    "frr-routing:ipv6");
}

DEFPY (interface_no_ipv6_mld,
       interface_no_ipv6_mld_cmd,
       "no ipv6 mld",
       NO_STR
       IPV6_STR
       IFACE_MLD_STR)
{
	const struct lyd_node *pim_enable_dnode;
	char pim_if_xpath[XPATH_MAXLEN + 20];

	snprintf(pim_if_xpath, sizeof(pim_if_xpath),
		 "%s/frr-pim:pim/address-family[address-family='%s']",
		 VTY_CURR_XPATH, "frr-routing:ipv6");

	pim_enable_dnode = yang_dnode_getf(vty->candidate_config->dnode,
					   FRR_PIM_ENABLE_XPATH, VTY_CURR_XPATH,
					   "frr-routing:ipv6");
	if (!pim_enable_dnode) {
		nb_cli_enqueue_change(vty, pim_if_xpath, NB_OP_DESTROY, NULL);
		nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);
	} else {
		if (!yang_dnode_get_bool(pim_enable_dnode, ".")) {
			nb_cli_enqueue_change(vty, pim_if_xpath, NB_OP_DESTROY,
					      NULL);
			nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);
		} else
			nb_cli_enqueue_change(vty, "./enable", NB_OP_MODIFY,
					      "false");
	}

	return nb_cli_apply_changes(vty, FRR_GMP_INTERFACE_XPATH,
				    "frr-routing:ipv6");
}

DEFPY (interface_ipv6_mld_version,
       interface_ipv6_mld_version_cmd,
       "ipv6 mld version (1-2)$version",
       IPV6_STR
       IFACE_MLD_STR
       "MLD version\n"
       "MLD version number\n")
{
	nb_cli_enqueue_change(vty, "./enable", NB_OP_MODIFY, "true");
	nb_cli_enqueue_change(vty, "./mld-version", NB_OP_MODIFY, version_str);

	return nb_cli_apply_changes(vty, FRR_GMP_INTERFACE_XPATH,
				    "frr-routing:ipv6");
}

DEFPY (interface_no_ipv6_mld_version,
       interface_no_ipv6_mld_version_cmd,
       "no ipv6 mld version [(1-2)]",
       NO_STR
       IPV6_STR
       IFACE_MLD_STR
       "MLD version\n"
       "MLD version number\n")
{
	nb_cli_enqueue_change(vty, "./mld-version", NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, FRR_GMP_INTERFACE_XPATH,
				    "frr-routing:ipv6");
}

DEFPY (interface_ipv6_mld_query_interval,
       interface_ipv6_mld_query_interval_cmd,
       "ipv6 mld query-interval (1-65535)$q_interval",
       IPV6_STR
       IFACE_MLD_STR
       IFACE_MLD_QUERY_INTERVAL_STR
       "Query interval in seconds\n")
{
	const struct lyd_node *pim_enable_dnode;

	pim_enable_dnode = yang_dnode_getf(vty->candidate_config->dnode,
					   FRR_PIM_ENABLE_XPATH, VTY_CURR_XPATH,
					   "frr-routing:ipv6");
	if (!pim_enable_dnode) {
		nb_cli_enqueue_change(vty, "./enable", NB_OP_MODIFY, "true");
	} else {
		if (!yang_dnode_get_bool(pim_enable_dnode, "."))
			nb_cli_enqueue_change(vty, "./enable", NB_OP_MODIFY,
					      "true");
	}

	nb_cli_enqueue_change(vty, "./query-interval", NB_OP_MODIFY,
			      q_interval_str);

	return nb_cli_apply_changes(vty, FRR_GMP_INTERFACE_XPATH,
				    "frr-routing:ipv6");
}

DEFPY (interface_no_ipv6_mld_query_interval,
      interface_no_ipv6_mld_query_interval_cmd,
      "no ipv6 mld query-interval [(1-65535)]",
      NO_STR
      IPV6_STR
      IFACE_MLD_STR
      IFACE_MLD_QUERY_INTERVAL_STR
      IGNORED_IN_NO_STR)
{
	nb_cli_enqueue_change(vty, "./query-interval", NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, FRR_GMP_INTERFACE_XPATH,
				    "frr-routing:ipv6");
}

void pim_cmd_init(void)
{
	if_cmd_init(pim_interface_config_write);

	install_element(CONFIG_NODE, &ipv6_pim_joinprune_time_cmd);
	install_element(CONFIG_NODE, &no_ipv6_pim_joinprune_time_cmd);
	install_element(CONFIG_NODE, &ipv6_pim_spt_switchover_infinity_cmd);
	install_element(CONFIG_NODE, &ipv6_pim_spt_switchover_infinity_plist_cmd);
	install_element(CONFIG_NODE, &no_ipv6_pim_spt_switchover_infinity_cmd);
	install_element(CONFIG_NODE, &no_ipv6_pim_spt_switchover_infinity_plist_cmd);
	install_element(CONFIG_NODE, &ipv6_pim_packets_cmd);
	install_element(CONFIG_NODE, &no_ipv6_pim_packets_cmd);
	install_element(CONFIG_NODE, &ipv6_pim_keep_alive_cmd);
	install_element(CONFIG_NODE, &no_ipv6_pim_keep_alive_cmd);
	install_element(CONFIG_NODE, &ipv6_pim_rp_keep_alive_cmd);
	install_element(CONFIG_NODE, &no_ipv6_pim_rp_keep_alive_cmd);
	install_element(CONFIG_NODE, &ipv6_pim_register_suppress_cmd);
	install_element(CONFIG_NODE, &no_ipv6_pim_register_suppress_cmd);
	install_element(INTERFACE_NODE, &interface_ipv6_pim_cmd);
	install_element(INTERFACE_NODE, &interface_no_ipv6_pim_cmd);
	install_element(INTERFACE_NODE, &interface_ipv6_pim_drprio_cmd);
	install_element(INTERFACE_NODE, &interface_no_ipv6_pim_drprio_cmd);
	install_element(INTERFACE_NODE, &interface_ipv6_pim_hello_cmd);
	install_element(INTERFACE_NODE, &interface_no_ipv6_pim_hello_cmd);
	install_element(INTERFACE_NODE, &interface_ipv6_pim_activeactive_cmd);
	install_element(INTERFACE_NODE, &interface_ipv6_pim_ssm_cmd);
	install_element(INTERFACE_NODE, &interface_no_ipv6_pim_ssm_cmd);
	install_element(INTERFACE_NODE, &interface_ipv6_pim_sm_cmd);
	install_element(INTERFACE_NODE, &interface_no_ipv6_pim_sm_cmd);
	install_element(INTERFACE_NODE,
			&interface_ipv6_pim_boundary_oil_cmd);
	install_element(INTERFACE_NODE,
			&interface_no_ipv6_pim_boundary_oil_cmd);
	install_element(INTERFACE_NODE, &interface_ipv6_mroute_cmd);
	install_element(INTERFACE_NODE, &interface_no_ipv6_mroute_cmd);
	install_element(CONFIG_NODE, &ipv6_pim_rp_cmd);
	install_element(VRF_NODE, &ipv6_pim_rp_cmd);
	install_element(CONFIG_NODE, &no_ipv6_pim_rp_cmd);
	install_element(VRF_NODE, &no_ipv6_pim_rp_cmd);
	install_element(CONFIG_NODE, &ipv6_pim_rp_prefix_list_cmd);
	install_element(VRF_NODE, &ipv6_pim_rp_prefix_list_cmd);
	install_element(CONFIG_NODE, &no_ipv6_pim_rp_prefix_list_cmd);
	install_element(VRF_NODE, &no_ipv6_pim_rp_prefix_list_cmd);
	install_element(INTERFACE_NODE, &interface_ipv6_mld_cmd);
	install_element(INTERFACE_NODE, &interface_no_ipv6_mld_cmd);
	install_element(INTERFACE_NODE, &interface_ipv6_mld_join_cmd);
	install_element(INTERFACE_NODE, &interface_no_ipv6_mld_join_cmd);
	install_element(INTERFACE_NODE, &interface_ipv6_mld_version_cmd);
	install_element(INTERFACE_NODE, &interface_no_ipv6_mld_version_cmd);
	install_element(INTERFACE_NODE, &interface_ipv6_mld_query_interval_cmd);
	install_element(INTERFACE_NODE,
			&interface_no_ipv6_mld_query_interval_cmd);
}
