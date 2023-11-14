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
#include "pim_cmd_common.h"
#include "pim_vty.h"
#include "lib/northbound_cli.h"
#include "pim_errors.h"
#include "pim_nb.h"
#include "pim_addr.h"
#include "pim_nht.h"
#include "pim_bsm.h"
#include "pim_iface.h"
#include "pim_zebra.h"
#include "pim_instance.h"

#ifndef VTYSH_EXTRACT_PL
#include "pimd/pim6_cmd_clippy.c"
#endif

static struct cmd_node debug_node = {
	.name = "debug",
	.node = DEBUG_NODE,
	.prompt = "",
	.config_write = pim_debug_config_write,
};

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
       "Rendezvous Point\n"
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
       "Rendezvous Point\n"
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
       "ipv6 pim [passive$passive]",
       IPV6_STR
       PIM_STR
       "Disable exchange of protocol packets\n")
{
	int ret;

	ret = pim_process_ip_pim_cmd(vty);

	if (ret != NB_OK)
		return ret;

	if (passive)
		return pim_process_ip_pim_passive_cmd(vty, true);

	return CMD_SUCCESS;
}

DEFPY (interface_no_ipv6_pim,
       interface_no_ipv6_pim_cmd,
       "no ipv6 pim [passive$passive]",
       NO_STR
       IPV6_STR
       PIM_STR
       "Disable exchange of protocol packets\n")
{
	if (passive)
		return pim_process_ip_pim_passive_cmd(vty, false);

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


DEFPY (ipv6_ssmpingd,
      ipv6_ssmpingd_cmd,
      "ipv6 ssmpingd [X:X::X:X]$source",
      IPV6_STR
      CONF_SSMPINGD_STR
      "Source address\n")
{
	const char *src_str = (source_str) ? source_str : "::";

	return pim_process_ssmpingd_cmd(vty, NB_OP_CREATE, src_str);
}


DEFPY (no_ipv6_ssmpingd,
      no_ipv6_ssmpingd_cmd,
      "no ipv6 ssmpingd [X:X::X:X]$source",
      NO_STR
      IPV6_STR
      CONF_SSMPINGD_STR
      "Source address\n")
{
	const char *src_str = (source_str) ? source_str : "::";

	return pim_process_ssmpingd_cmd(vty, NB_OP_DESTROY, src_str);
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
	char pim_if_xpath[XPATH_MAXLEN + 64];

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

DEFPY (ipv6_mld_group_watermark,
       ipv6_mld_group_watermark_cmd,
       "ipv6 mld watermark-warn (1-65535)$limit",
       IPV6_STR
       MLD_STR
       "Configure group limit for watermark warning\n"
       "Group count to generate watermark warning\n")
{
	PIM_DECLVAR_CONTEXT_VRF(vrf, pim);

	/* TBD Depends on MLD data structure changes */
	(void)pim;

	return CMD_SUCCESS;
}

DEFPY (no_ipv6_mld_group_watermark,
       no_ipv6_mld_group_watermark_cmd,
       "no ipv6 mld watermark-warn [(1-65535)$limit]",
       NO_STR
       IPV6_STR
       MLD_STR
       "Unconfigure group limit for watermark warning\n"
       IGNORED_IN_NO_STR)
{
	PIM_DECLVAR_CONTEXT_VRF(vrf, pim);

	/* TBD Depends on MLD data structure changes */
	(void)pim;

	return CMD_SUCCESS;
}

DEFPY (interface_ipv6_mld_query_max_response_time,
       interface_ipv6_mld_query_max_response_time_cmd,
       "ipv6 mld query-max-response-time (1-65535)$qmrt",
       IPV6_STR
       IFACE_MLD_STR
       IFACE_MLD_QUERY_MAX_RESPONSE_TIME_STR
       "Query response value in milliseconds\n")
{
	return gm_process_query_max_response_time_cmd(vty, qmrt_str);
}

DEFPY (interface_no_ipv6_mld_query_max_response_time,
       interface_no_ipv6_mld_query_max_response_time_cmd,
       "no ipv6 mld query-max-response-time [(1-65535)]",
       NO_STR
       IPV6_STR
       IFACE_MLD_STR
       IFACE_MLD_QUERY_MAX_RESPONSE_TIME_STR
       IGNORED_IN_NO_STR)
{
	return gm_process_no_query_max_response_time_cmd(vty);
}

DEFPY (interface_ipv6_mld_last_member_query_count,
       interface_ipv6_mld_last_member_query_count_cmd,
       "ipv6 mld last-member-query-count (1-255)$lmqc",
       IPV6_STR
       IFACE_MLD_STR
       IFACE_MLD_LAST_MEMBER_QUERY_COUNT_STR
       "Last member query count\n")
{
	return gm_process_last_member_query_count_cmd(vty, lmqc_str);
}

DEFPY (interface_no_ipv6_mld_last_member_query_count,
       interface_no_ipv6_mld_last_member_query_count_cmd,
       "no ipv6 mld last-member-query-count [(1-255)]",
       NO_STR
       IPV6_STR
       IFACE_MLD_STR
       IFACE_MLD_LAST_MEMBER_QUERY_COUNT_STR
       IGNORED_IN_NO_STR)
{
	return gm_process_no_last_member_query_count_cmd(vty);
}

DEFPY (interface_ipv6_mld_last_member_query_interval,
       interface_ipv6_mld_last_member_query_interval_cmd,
       "ipv6 mld last-member-query-interval (1-65535)$lmqi",
       IPV6_STR
       IFACE_MLD_STR
       IFACE_MLD_LAST_MEMBER_QUERY_INTERVAL_STR
       "Last member query interval in deciseconds\n")
{
	return gm_process_last_member_query_interval_cmd(vty, lmqi_str);
}

DEFPY (interface_no_ipv6_mld_last_member_query_interval,
       interface_no_ipv6_mld_last_member_query_interval_cmd,
       "no ipv6 mld last-member-query-interval [(1-65535)]",
       NO_STR
       IPV6_STR
       IFACE_MLD_STR
       IFACE_MLD_LAST_MEMBER_QUERY_INTERVAL_STR
       IGNORED_IN_NO_STR)
{
	return gm_process_no_last_member_query_interval_cmd(vty);
}

DEFPY (show_ipv6_pim_rp,
       show_ipv6_pim_rp_cmd,
       "show ipv6 pim [vrf NAME] rp-info [X:X::X:X/M$group] [json$json]",
       SHOW_STR
       IPV6_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "PIM RP information\n"
       "Multicast Group range\n"
       JSON_STR)
{
	struct pim_instance *pim;
	struct vrf *v;
	json_object *json_parent = NULL;
	struct prefix *range = NULL;

	v = vrf_lookup_by_name(vrf ? vrf : VRF_DEFAULT_NAME);

	if (!v)
		return CMD_WARNING;

	pim = pim_get_pim_instance(v->vrf_id);

	if (!pim) {
		vty_out(vty, "%% Unable to find pim instance\n");
		return CMD_WARNING;
	}

	if (group_str) {
		range = prefix_new();
		prefix_copy(range, group);
		apply_mask(range);
	}

	if (json)
		json_parent = json_object_new_object();

	pim_rp_show_information(pim, range, vty, json_parent);

	if (json)
		vty_json(vty, json_parent);

	prefix_free(&range);

	return CMD_SUCCESS;
}

DEFPY (show_ipv6_pim_rp_vrf_all,
       show_ipv6_pim_rp_vrf_all_cmd,
       "show ipv6 pim vrf all rp-info [X:X::X:X/M$group] [json$json]",
       SHOW_STR
       IPV6_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "PIM RP information\n"
       "Multicast Group range\n"
       JSON_STR)
{
	struct vrf *vrf;
	json_object *json_parent = NULL;
	json_object *json_vrf = NULL;
	struct prefix *range = NULL;

	if (group_str) {
		range = prefix_new();
		prefix_copy(range, group);
		apply_mask(range);
	}

	if (json)
		json_parent = json_object_new_object();

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		if (!json)
			vty_out(vty, "VRF: %s\n", vrf->name);
		else
			json_vrf = json_object_new_object();
		pim_rp_show_information(vrf->info, range, vty, json_vrf);
		if (json)
			json_object_object_add(json_parent, vrf->name,
					       json_vrf);
	}
	if (json)
		vty_json(vty, json_parent);

	prefix_free(&range);

	return CMD_SUCCESS;
}

DEFPY (show_ipv6_pim_rpf,
       show_ipv6_pim_rpf_cmd,
       "show ipv6 pim [vrf NAME] rpf [json$json]",
       SHOW_STR
       IPV6_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "PIM cached source rpf information\n"
       JSON_STR)
{
	struct pim_instance *pim;
	struct vrf *v;
	json_object *json_parent = NULL;

	v = vrf_lookup_by_name(vrf ? vrf : VRF_DEFAULT_NAME);

	if (!v)
		return CMD_WARNING;

	pim = pim_get_pim_instance(v->vrf_id);

	if (!pim) {
		vty_out(vty, "%% Unable to find pim instance\n");
		return CMD_WARNING;
	}

	if (json)
		json_parent = json_object_new_object();

	pim_show_rpf(pim, vty, json_parent);

	if (json)
		vty_json(vty, json_parent);

	return CMD_SUCCESS;
}

DEFPY (show_ipv6_pim_rpf_vrf_all,
       show_ipv6_pim_rpf_vrf_all_cmd,
       "show ipv6 pim vrf all rpf [json$json]",
       SHOW_STR
       IPV6_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "PIM cached source rpf information\n"
       JSON_STR)
{
	struct vrf *vrf;
	json_object *json_parent = NULL;
	json_object *json_vrf = NULL;

	if (json)
		json_parent = json_object_new_object();

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		if (!json)
			vty_out(vty, "VRF: %s\n", vrf->name);
		else
			json_vrf = json_object_new_object();
		pim_show_rpf(vrf->info, vty, json_vrf);
		if (json)
			json_object_object_add(json_parent, vrf->name,
					       json_vrf);
	}
	if (json)
		vty_json(vty, json_parent);

	return CMD_SUCCESS;
}

DEFPY (show_ipv6_pim_secondary,
       show_ipv6_pim_secondary_cmd,
       "show ipv6 pim [vrf NAME] secondary",
       SHOW_STR
       IPV6_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "PIM neighbor addresses\n")
{
	struct pim_instance *pim;
	struct vrf *v;

	v = vrf_lookup_by_name(vrf ? vrf : VRF_DEFAULT_NAME);

	if (!v)
		return CMD_WARNING;

	pim = pim_get_pim_instance(v->vrf_id);

	if (!pim) {
		vty_out(vty, "%% Unable to find pim instance\n");
		return CMD_WARNING;
	}

	pim_show_neighbors_secondary(pim, vty);

	return CMD_SUCCESS;
}

DEFPY (show_ipv6_pim_statistics,
       show_ipv6_pim_statistics_cmd,
       "show ipv6 pim [vrf NAME] statistics [interface WORD$word] [json$json]",
       SHOW_STR
       IPV6_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "PIM statistics\n"
       INTERFACE_STR
       "PIM interface\n"
       JSON_STR)
{
	struct pim_instance *pim;
	struct vrf *v;
	bool uj = !!json;

	v = vrf_lookup_by_name(vrf ? vrf : VRF_DEFAULT_NAME);

	if (!v)
		return CMD_WARNING;

	pim = pim_get_pim_instance(v->vrf_id);

	if (!pim) {
		vty_out(vty, "%% Unable to find pim instance\n");
		return CMD_WARNING;
	}

	if (word)
		pim_show_statistics(pim, vty, word, uj);
	else
		pim_show_statistics(pim, vty, NULL, uj);

	return CMD_SUCCESS;
}

DEFPY (show_ipv6_pim_upstream,
       show_ipv6_pim_upstream_cmd,
       "show ipv6 pim [vrf NAME] upstream [X:X::X:X$s_or_g [X:X::X:X$g]] [json$json]",
       SHOW_STR
       IPV6_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "PIM upstream information\n"
       "The Source or Group\n"
       "The Group\n"
       JSON_STR)
{
	pim_sgaddr sg = {0};
	struct vrf *v;
	bool uj = !!json;
	struct pim_instance *pim;
	json_object *json_parent = NULL;

	v = vrf_lookup_by_name(vrf ? vrf : VRF_DEFAULT_NAME);

	if (!v) {
		vty_out(vty, "%% Vrf specified: %s does not exist\n", vrf);
		return CMD_WARNING;
	}
	pim = pim_get_pim_instance(v->vrf_id);

	if (!pim) {
		vty_out(vty, "%% Unable to find pim instance\n");
		return CMD_WARNING;
	}

	if (uj)
		json_parent = json_object_new_object();

	if (!pim_addr_is_any(s_or_g)) {
		if (!pim_addr_is_any(g)) {
			sg.src = s_or_g;
			sg.grp = g;
		} else
			sg.grp = s_or_g;
	}

	pim_show_upstream(pim, vty, &sg, json_parent);

	if (uj)
		vty_json(vty, json_parent);

	return CMD_SUCCESS;
}

DEFPY (show_ipv6_pim_upstream_vrf_all,
       show_ipv6_pim_upstream_vrf_all_cmd,
       "show ipv6 pim vrf all upstream [json$json]",
       SHOW_STR
       IPV6_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "PIM upstream information\n"
       JSON_STR)
{
	pim_sgaddr sg = {0};
	struct vrf *vrf;
	json_object *json_parent = NULL;
	json_object *json_vrf = NULL;

	if (json)
		json_parent = json_object_new_object();

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		if (!json)
			vty_out(vty, "VRF: %s\n", vrf->name);
		else
			json_vrf = json_object_new_object();
		pim_show_upstream(vrf->info, vty, &sg, json_vrf);
		if (json)
			json_object_object_add(json_parent, vrf->name,
					       json_vrf);
	}

	if (json)
		vty_json(vty, json_parent);

	return CMD_SUCCESS;
}

DEFPY (show_ipv6_pim_upstream_join_desired,
       show_ipv6_pim_upstream_join_desired_cmd,
       "show ipv6 pim [vrf NAME] upstream-join-desired [json$json]",
       SHOW_STR
       IPV6_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "PIM upstream join-desired\n"
       JSON_STR)
{
	struct pim_instance *pim;
	struct vrf *v;
	bool uj = !!json;

	v = vrf_lookup_by_name(vrf ? vrf : VRF_DEFAULT_NAME);

	if (!v)
		return CMD_WARNING;

	pim = pim_get_pim_instance(v->vrf_id);

	if (!pim) {
		vty_out(vty, "%% Unable to find pim instance\n");
		return CMD_WARNING;
	}

	pim_show_join_desired(pim, vty, uj);

	return CMD_SUCCESS;
}

DEFPY (show_ipv6_pim_upstream_rpf,
       show_ipv6_pim_upstream_rpf_cmd,
       "show ipv6 pim [vrf NAME] upstream-rpf [json$json]",
       SHOW_STR
       IPV6_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "PIM upstream source rpf\n"
       JSON_STR)
{
	struct pim_instance *pim;
	struct vrf *v;
	bool uj = !!json;

	v = vrf_lookup_by_name(vrf ? vrf : VRF_DEFAULT_NAME);

	if (!v)
		return CMD_WARNING;

	pim = pim_get_pim_instance(v->vrf_id);

	if (!pim) {
		vty_out(vty, "%% Unable to find pim instance\n");
		return CMD_WARNING;
	}

	pim_show_upstream_rpf(pim, vty, uj);

	return CMD_SUCCESS;
}

DEFPY (show_ipv6_pim_state,
       show_ipv6_pim_state_cmd,
       "show ipv6 pim [vrf NAME] state [X:X::X:X$s_or_g [X:X::X:X$g]] [json$json]",
       SHOW_STR
       IPV6_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "PIM state information\n"
       "Unicast or Multicast address\n"
       "Multicast address\n"
       JSON_STR)
{
	struct pim_instance *pim;
	struct vrf *v;
	json_object *json_parent = NULL;

	v = vrf_lookup_by_name(vrf ? vrf : VRF_DEFAULT_NAME);

	if (!v)
		return CMD_WARNING;

	pim = pim_get_pim_instance(v->vrf_id);

	if (!pim) {
		vty_out(vty, "%% Unable to find pim instance\n");
		return CMD_WARNING;
	}

	if (json)
		json_parent = json_object_new_object();

	pim_show_state(pim, vty, s_or_g_str, g_str, json_parent);

	if (json)
		vty_json(vty, json_parent);

	return CMD_SUCCESS;
}

DEFPY (show_ipv6_pim_state_vrf_all,
       show_ipv6_pim_state_vrf_all_cmd,
       "show ipv6 pim vrf all state [X:X::X:X$s_or_g [X:X::X:X$g]] [json$json]",
       SHOW_STR
       IPV6_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "PIM state information\n"
       "Unicast or Multicast address\n"
       "Multicast address\n"
       JSON_STR)
{
	struct vrf *vrf;
	json_object *json_parent = NULL;
	json_object *json_vrf = NULL;

	if (json)
		json_parent = json_object_new_object();

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		if (!json)
			vty_out(vty, "VRF: %s\n", vrf->name);
		else
			json_vrf = json_object_new_object();
		pim_show_state(vrf->info, vty, s_or_g_str, g_str, json_vrf);
		if (json)
			json_object_object_add(json_parent, vrf->name,
					       json_vrf);
	}
	if (json)
		vty_json(vty, json_parent);

	return CMD_SUCCESS;
}

DEFPY (show_ipv6_pim_channel,
       show_ipv6_pim_channel_cmd,
       "show ipv6 pim [vrf NAME] channel [json$json]",
       SHOW_STR
       IPV6_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "PIM downstream channel info\n"
       JSON_STR)
{
	struct vrf *v;
	bool uj = !!json;

	v = vrf_lookup_by_name(vrf ? vrf : VRF_DEFAULT_NAME);

	if (!v)
		return CMD_WARNING;

	pim_show_channel(v->info, vty, uj);

	return CMD_SUCCESS;
}

DEFPY (show_ipv6_pim_interface,
       show_ipv6_pim_interface_cmd,
       "show ipv6 pim [vrf NAME] interface [detail|WORD]$interface [json$json]",
       SHOW_STR
       IPV6_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "PIM interface information\n"
       "Detailed output\n"
       "interface name\n"
       JSON_STR)
{
	struct vrf *v;
	bool uj = !!json;
	json_object *json_parent = NULL;

	v = vrf_lookup_by_name(vrf ? vrf : VRF_DEFAULT_NAME);

	if (!v)
		return CMD_WARNING;

	if (uj)
		json_parent = json_object_new_object();

	if (interface)
		pim_show_interfaces_single(v->info, vty, interface, false,
					   json_parent);
	else
		pim_show_interfaces(v->info, vty, false, json_parent);

	if (uj)
		vty_json(vty, json_parent);

	return CMD_SUCCESS;
}

DEFPY (show_ipv6_pim_interface_vrf_all,
       show_ipv6_pim_interface_vrf_all_cmd,
       "show ipv6 pim vrf all interface [detail|WORD]$interface [json$json]",
       SHOW_STR
       IPV6_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "PIM interface information\n"
       "Detailed output\n"
       "interface name\n"
       JSON_STR)
{
	bool uj = !!json;
	struct vrf *v;
	json_object *json_parent = NULL;
	json_object *json_vrf = NULL;

	if (uj)
		json_parent = json_object_new_object();

	RB_FOREACH (v, vrf_name_head, &vrfs_by_name) {
		if (!uj)
			vty_out(vty, "VRF: %s\n", v->name);
		else
			json_vrf = json_object_new_object();

		if (interface)
			pim_show_interfaces_single(v->info, vty, interface,
						   false, json_vrf);
		else
			pim_show_interfaces(v->info, vty, false, json_vrf);

		if (uj)
			json_object_object_add(json_parent, v->name, json_vrf);
	}
	if (uj)
		vty_json(vty, json_parent);

	return CMD_SUCCESS;
}

DEFPY (show_ipv6_pim_join,
       show_ipv6_pim_join_cmd,
       "show ipv6 pim [vrf NAME] join [X:X::X:X$s_or_g [X:X::X:X$g]] [json$json]",
       SHOW_STR
       IPV6_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "PIM interface join information\n"
       "The Source or Group\n"
       "The Group\n"
       JSON_STR)
{
	pim_sgaddr sg = {};
	struct vrf *v;
	struct pim_instance *pim;
	json_object *json_parent = NULL;

	v = vrf_lookup_by_name(vrf ? vrf : VRF_DEFAULT_NAME);

	if (!v) {
		vty_out(vty, "%% Vrf specified: %s does not exist\n", vrf);
		return CMD_WARNING;
	}
	pim = pim_get_pim_instance(v->vrf_id);

	if (!pim) {
		vty_out(vty, "%% Unable to find pim instance\n");
		return CMD_WARNING;
	}

	if (!pim_addr_is_any(s_or_g)) {
		if (!pim_addr_is_any(g)) {
			sg.src = s_or_g;
			sg.grp = g;
		} else
			sg.grp = s_or_g;
	}

	if (json)
		json_parent = json_object_new_object();

	pim_show_join(pim, vty, &sg, json_parent);

	if (json)
		vty_json(vty, json_parent);

	return CMD_SUCCESS;
}

DEFPY (show_ipv6_pim_join_vrf_all,
       show_ipv6_pim_join_vrf_all_cmd,
       "show ipv6 pim vrf all join [json$json]",
       SHOW_STR
       IPV6_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "PIM interface join information\n"
       JSON_STR)
{
	pim_sgaddr sg = {0};
	struct vrf *vrf_struct;
	json_object *json_parent = NULL;
	json_object *json_vrf = NULL;

	if (json)
		json_parent = json_object_new_object();

	RB_FOREACH (vrf_struct, vrf_name_head, &vrfs_by_name) {
		if (!json_parent)
			vty_out(vty, "VRF: %s\n", vrf_struct->name);
		else
			json_vrf = json_object_new_object();
		pim_show_join(vrf_struct->info, vty, &sg, json_vrf);

		if (json)
			json_object_object_add(json_parent, vrf_struct->name,
					       json_vrf);
	}
	if (json)
		vty_json(vty, json_parent);

	return CMD_WARNING;
}

DEFPY (show_ipv6_pim_jp_agg,
       show_ipv6_pim_jp_agg_cmd,
       "show ipv6 pim [vrf NAME] jp-agg",
       SHOW_STR
       IPV6_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "join prune aggregation list\n")
{
	struct vrf *v;
	struct pim_instance *pim;

	v = vrf_lookup_by_name(vrf ? vrf : VRF_DEFAULT_NAME);

	if (!v) {
		vty_out(vty, "%% Vrf specified: %s does not exist\n", vrf);
		return CMD_WARNING;
	}
	pim = pim_get_pim_instance(v->vrf_id);

	if (!pim) {
		vty_out(vty, "%% Unable to find pim instance\n");
		return CMD_WARNING;
	}

	pim_show_jp_agg_list(pim, vty);

	return CMD_SUCCESS;
}

DEFPY (show_ipv6_pim_local_membership,
       show_ipv6_pim_local_membership_cmd,
       "show ipv6 pim [vrf NAME] local-membership [json$json]",
       SHOW_STR
       IPV6_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "PIM interface local-membership\n"
       JSON_STR)
{
	struct vrf *v;
	bool uj = !!json;

	v = vrf_lookup_by_name(vrf ? vrf : VRF_DEFAULT_NAME);

	if (!v)
		return CMD_WARNING;

	pim_show_membership(v->info, vty, uj);

	return CMD_SUCCESS;
}

DEFPY (show_ipv6_pim_neighbor,
       show_ipv6_pim_neighbor_cmd,
       "show ipv6 pim [vrf NAME] neighbor [detail|WORD]$interface [json$json]",
       SHOW_STR
       IPV6_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "PIM neighbor information\n"
       "Detailed output\n"
       "Name of interface or neighbor\n"
       JSON_STR)
{
	struct vrf *v;
	json_object *json_parent = NULL;

	v = vrf_lookup_by_name(vrf ? vrf : VRF_DEFAULT_NAME);

	if (!v)
		return CMD_WARNING;

	if (json)
		json_parent = json_object_new_object();

	if (interface)
		pim_show_neighbors_single(v->info, vty, interface, json_parent);
	else
		pim_show_neighbors(v->info, vty, json_parent);

	if (json)
		vty_json(vty, json_parent);

	return CMD_SUCCESS;
}

DEFPY (show_ipv6_pim_neighbor_vrf_all,
       show_ipv6_pim_neighbor_vrf_all_cmd,
       "show ipv6 pim vrf all neighbor [detail|WORD]$interface [json$json]",
       SHOW_STR
       IPV6_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "PIM neighbor information\n"
       "Detailed output\n"
       "Name of interface or neighbor\n"
       JSON_STR)
{
	struct vrf *v;
	json_object *json_parent = NULL;
	json_object *json_vrf = NULL;

	if (json)
		json_parent = json_object_new_object();
	RB_FOREACH (v, vrf_name_head, &vrfs_by_name) {
		if (!json)
			vty_out(vty, "VRF: %s\n", v->name);
		else
			json_vrf = json_object_new_object();

		if (interface)
			pim_show_neighbors_single(v->info, vty, interface,
						  json_vrf);
		else
			pim_show_neighbors(v->info, vty, json_vrf);

		if (json)
			json_object_object_add(json_parent, v->name, json_vrf);
	}
	if (json)
		vty_json(vty, json_parent);

	return CMD_SUCCESS;
}

DEFPY (show_ipv6_pim_nexthop,
       show_ipv6_pim_nexthop_cmd,
       "show ipv6 pim [vrf NAME] nexthop",
       SHOW_STR
       IPV6_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "PIM cached nexthop rpf information\n")
{
	struct vrf *v;

	v = vrf_lookup_by_name(vrf ? vrf : VRF_DEFAULT_NAME);

	if (!v)
		return CMD_WARNING;

	pim_show_nexthop(v->info, vty);

	return CMD_SUCCESS;
}

DEFPY (show_ipv6_pim_nexthop_lookup,
       show_ipv6_pim_nexthop_lookup_cmd,
       "show ipv6 pim [vrf NAME] nexthop-lookup X:X::X:X$source X:X::X:X$group",
       SHOW_STR
       IPV6_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "PIM cached nexthop rpf lookup\n"
       "Source/RP address\n"
       "Multicast Group address\n")
{
	struct prefix nht_p;
	int result = 0;
	pim_addr vif_source;
	struct prefix grp;
	struct pim_nexthop nexthop;
	struct vrf *v;

	v = vrf_lookup_by_name(vrf ? vrf : VRF_DEFAULT_NAME);

	if (!v)
		return CMD_WARNING;

	if (!pim_rp_set_upstream_addr(v->info, &vif_source, source, group))
		return CMD_SUCCESS;

	pim_addr_to_prefix(&nht_p, vif_source);
	pim_addr_to_prefix(&grp, group);
	memset(&nexthop, 0, sizeof(nexthop));

	result = pim_ecmp_nexthop_lookup(v->info, &nexthop, &nht_p, &grp, 0);

	if (!result) {
		vty_out(vty,
			"Nexthop Lookup failed, no usable routes returned.\n");
		return CMD_SUCCESS;
	}

	vty_out(vty, "Group %s --- Nexthop %pPAs Interface %s\n", group_str,
		&nexthop.mrib_nexthop_addr, nexthop.interface->name);

	return CMD_SUCCESS;
}

DEFPY (show_ipv6_multicast,
       show_ipv6_multicast_cmd,
       "show ipv6 multicast [vrf NAME]",
       SHOW_STR
       IPV6_STR
       "Multicast global information\n"
       VRF_CMD_HELP_STR)
{
	struct vrf *v;
	struct pim_instance *pim;

	v = vrf_lookup_by_name(vrf ? vrf : VRF_DEFAULT_NAME);

	if (!v)
		return CMD_WARNING;

	pim = pim_get_pim_instance(v->vrf_id);

	if (!pim) {
		vty_out(vty, "%% Unable to find pim instance\n");
		return CMD_WARNING;
	}

	pim_cmd_show_ip_multicast_helper(pim, vty);

	return CMD_SUCCESS;
}

DEFPY (show_ipv6_multicast_vrf_all,
       show_ipv6_multicast_vrf_all_cmd,
       "show ipv6 multicast vrf all",
       SHOW_STR
       IPV6_STR
       "Multicast global information\n"
       VRF_CMD_HELP_STR)
{
	struct vrf *vrf;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		vty_out(vty, "VRF: %s\n", vrf->name);
		pim_cmd_show_ip_multicast_helper(vrf->info, vty);
	}

	return CMD_SUCCESS;
}

DEFPY (show_ipv6_multicast_count,
       show_ipv6_multicast_count_cmd,
       "show ipv6 multicast count [vrf NAME] [json$json]",
       SHOW_STR
       IPV6_STR
       "Multicast global information\n"
       "Data packet count\n"
       VRF_CMD_HELP_STR
       JSON_STR)
{
	struct pim_instance *pim;
	struct vrf *v;
	json_object *json_parent = NULL;

	v = vrf_lookup_by_name(vrf ? vrf : VRF_DEFAULT_NAME);

	if (!v)
		return CMD_WARNING;

	pim = pim_get_pim_instance(v->vrf_id);

	if (!pim) {
		vty_out(vty, "%% Unable to find pim instance\n");
		return CMD_WARNING;
	}

	if (json)
		json_parent = json_object_new_object();

	show_multicast_interfaces(pim, vty, json_parent);

	if (json)
		vty_json(vty, json_parent);

	return CMD_SUCCESS;
}

DEFPY (show_ipv6_multicast_count_vrf_all,
       show_ipv6_multicast_count_vrf_all_cmd,
       "show ipv6 multicast count vrf all [json$json]",
       SHOW_STR
       IPV6_STR
       "Multicast global information\n"
       "Data packet count\n"
       VRF_CMD_HELP_STR
       JSON_STR)
{
	struct vrf *vrf;
	json_object *json_parent = NULL;
	json_object *json_vrf = NULL;

	if (json)
		json_parent = json_object_new_object();

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		if (!json)
			vty_out(vty, "VRF: %s\n", vrf->name);
		else
			json_vrf = json_object_new_object();

		show_multicast_interfaces(vrf->info, vty, json_vrf);
		if (json)
			json_object_object_add(json_parent, vrf->name,
					       json_vrf);
	}
	if (json)
		vty_json(vty, json_parent);

	return CMD_SUCCESS;
}

DEFPY (show_ipv6_mroute,
       show_ipv6_mroute_cmd,
       "show ipv6 mroute [vrf NAME] [X:X::X:X$s_or_g [X:X::X:X$g]] [fill$fill] [json$json]",
       SHOW_STR
       IPV6_STR
       MROUTE_STR
       VRF_CMD_HELP_STR
       "The Source or Group\n"
       "The Group\n"
       "Fill in Assumed data\n"
       JSON_STR)
{
	pim_sgaddr sg = {0};
	struct pim_instance *pim;
	struct vrf *v;
	json_object *json_parent = NULL;

	v = vrf_lookup_by_name(vrf ? vrf : VRF_DEFAULT_NAME);

	if (!v)
		return CMD_WARNING;

	pim = pim_get_pim_instance(v->vrf_id);

	if (!pim) {
		vty_out(vty, "%% Unable to find pim instance\n");
		return CMD_WARNING;
	}

	if (json)
		json_parent = json_object_new_object();

	if (!pim_addr_is_any(s_or_g)) {
		if (!pim_addr_is_any(g)) {
			sg.src = s_or_g;
			sg.grp = g;
		} else
			sg.grp = s_or_g;
	}

	show_mroute(pim, vty, &sg, !!fill, json_parent);

	if (json)
		vty_json(vty, json_parent);

	return CMD_SUCCESS;
}

DEFPY (show_ipv6_mroute_vrf_all,
       show_ipv6_mroute_vrf_all_cmd,
       "show ipv6 mroute vrf all [fill$fill] [json$json]",
       SHOW_STR
       IPV6_STR
       MROUTE_STR
       VRF_CMD_HELP_STR
       "Fill in Assumed data\n"
       JSON_STR)
{
	pim_sgaddr sg = {0};
	struct vrf *vrf;
	json_object *json_parent = NULL;
	json_object *json_vrf = NULL;

	if (json)
		json_parent = json_object_new_object();

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		if (!json)
			vty_out(vty, "VRF: %s\n", vrf->name);
		else
			json_vrf = json_object_new_object();
		show_mroute(vrf->info, vty, &sg, !!fill, json_vrf);
		if (json)
			json_object_object_add(json_parent, vrf->name,
					       json_vrf);
	}
	if (json)
		vty_json(vty, json_parent);

	return CMD_SUCCESS;
}

DEFPY (show_ipv6_mroute_count,
       show_ipv6_mroute_count_cmd,
       "show ipv6 mroute [vrf NAME] count [json$json]",
       SHOW_STR
       IPV6_STR
       MROUTE_STR
       VRF_CMD_HELP_STR
       "Route and packet count data\n"
       JSON_STR)
{
	struct pim_instance *pim;
	struct vrf *v;
	json_object *json_parent = NULL;

	v = vrf_lookup_by_name(vrf ? vrf : VRF_DEFAULT_NAME);

	if (!v)
		return CMD_WARNING;

	pim = pim_get_pim_instance(v->vrf_id);

	if (!pim) {
		vty_out(vty, "%% Unable to find pim instance\n");
		return CMD_WARNING;
	}

	if (json)
		json_parent = json_object_new_object();

	show_mroute_count(pim, vty, json_parent);

	if (json)
		vty_json(vty, json_parent);

	return CMD_SUCCESS;
}

DEFPY (show_ipv6_mroute_count_vrf_all,
       show_ipv6_mroute_count_vrf_all_cmd,
       "show ipv6 mroute vrf all count [json$json]",
       SHOW_STR
       IPV6_STR
       MROUTE_STR
       VRF_CMD_HELP_STR
       "Route and packet count data\n"
       JSON_STR)
{
	struct vrf *vrf;
	json_object *json_parent = NULL;
	json_object *json_vrf = NULL;

	if (json)
		json_parent = json_object_new_object();

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		if (!json)
			vty_out(vty, "VRF: %s\n", vrf->name);
		else
			json_vrf = json_object_new_object();
		show_mroute_count(vrf->info, vty, json_vrf);

		if (json)
			json_object_object_add(json_parent, vrf->name,
					       json_vrf);
	}

	if (json)
		vty_json(vty, json_parent);

	return CMD_SUCCESS;
}

DEFPY (show_ipv6_mroute_summary,
       show_ipv6_mroute_summary_cmd,
       "show ipv6 mroute [vrf NAME] summary [json$json]",
       SHOW_STR
       IPV6_STR
       MROUTE_STR
       VRF_CMD_HELP_STR
       "Summary of all mroutes\n"
       JSON_STR)
{
	struct pim_instance *pim;
	struct vrf *v;
	json_object *json_parent = NULL;

	v = vrf_lookup_by_name(vrf ? vrf : VRF_DEFAULT_NAME);

	if (!v)
		return CMD_WARNING;

	pim = pim_get_pim_instance(v->vrf_id);

	if (!pim) {
		vty_out(vty, "%% Unable to find pim instance\n");
		return CMD_WARNING;
	}

	if (json)
		json_parent = json_object_new_object();

	show_mroute_summary(pim, vty, json_parent);

	if (json)
		vty_json(vty, json_parent);

	return CMD_SUCCESS;
}

DEFPY (show_ipv6_mroute_summary_vrf_all,
       show_ipv6_mroute_summary_vrf_all_cmd,
       "show ipv6 mroute vrf all summary [json$json]",
       SHOW_STR
       IPV6_STR
       MROUTE_STR
       VRF_CMD_HELP_STR
       "Summary of all mroutes\n"
       JSON_STR)
{
	struct vrf *vrf;
	json_object *json_parent = NULL;
	json_object *json_vrf = NULL;

	if (json)
		json_parent = json_object_new_object();

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		if (!json)
			vty_out(vty, "VRF: %s\n", vrf->name);
		else
			json_vrf = json_object_new_object();

		show_mroute_summary(vrf->info, vty, json_vrf);

		if (json)
			json_object_object_add(json_parent, vrf->name,
					       json_vrf);
	}

	if (json)
		vty_json(vty, json_parent);

	return CMD_SUCCESS;
}

DEFPY (clear_ipv6_pim_statistics,
       clear_ipv6_pim_statistics_cmd,
       "clear ipv6 pim statistics [vrf NAME]$name",
       CLEAR_STR
       IPV6_STR
       CLEAR_IP_PIM_STR
       VRF_CMD_HELP_STR
       "Reset PIM statistics\n")
{
	struct vrf *v = pim_cmd_lookup(vty, name);

	if (!v)
		return CMD_WARNING;

	clear_pim_statistics(v->info);

	return CMD_SUCCESS;
}

DEFPY (clear_ipv6_mroute,
       clear_ipv6_mroute_cmd,
       "clear ipv6 mroute [vrf NAME]$name",
       CLEAR_STR
       IPV6_STR
       "Reset multicast routes\n"
       VRF_CMD_HELP_STR)
{
	struct vrf *v = pim_cmd_lookup(vty, name);

	if (!v)
		return CMD_WARNING;

	clear_mroute(v->info);

	return CMD_SUCCESS;
}

DEFPY (clear_ipv6_pim_oil,
       clear_ipv6_pim_oil_cmd,
       "clear ipv6 pim [vrf NAME]$name oil",
       CLEAR_STR
       IPV6_STR
       CLEAR_IP_PIM_STR
       VRF_CMD_HELP_STR
       "Rescan PIMv6 OIL (output interface list)\n")
{
	struct vrf *v = pim_cmd_lookup(vty, name);

	if (!v)
		return CMD_WARNING;

	pim_scan_oil(v->info);

	return CMD_SUCCESS;
}

DEFPY (clear_ipv6_mroute_count,
       clear_ipv6_mroute_count_cmd,
       "clear ipv6 mroute [vrf NAME]$name count",
       CLEAR_STR
       IPV6_STR
       MROUTE_STR
       VRF_CMD_HELP_STR
       "Route and packet count data\n")
{
	return clear_ip_mroute_count_command(vty, name);
}

DEFPY (debug_pimv6,
       debug_pimv6_cmd,
       "[no] debug pimv6",
       NO_STR
       DEBUG_STR
       DEBUG_PIMV6_STR)
{
	if (!no)
		return pim_debug_pim_cmd();
	else
		return pim_no_debug_pim_cmd();
}

DEFPY (debug_pimv6_nht,
       debug_pimv6_nht_cmd,
       "[no] debug pimv6 nht",
       NO_STR
       DEBUG_STR
       DEBUG_PIMV6_STR
       "Nexthop Tracking\n")
{
	if (!no)
		PIM_DO_DEBUG_PIM_NHT;
	else
		PIM_DONT_DEBUG_PIM_NHT;
	return CMD_SUCCESS;
}

DEFPY (debug_pimv6_nht_det,
       debug_pimv6_nht_det_cmd,
       "[no] debug pimv6 nht detail",
       NO_STR
       DEBUG_STR
       DEBUG_PIMV6_STR
       "Nexthop Tracking\n"
       "Detailed Information\n")
{
	if (!no)
		PIM_DO_DEBUG_PIM_NHT_DETAIL;
	else
		PIM_DONT_DEBUG_PIM_NHT_DETAIL;
	return CMD_SUCCESS;
}

DEFPY (debug_pimv6_events,
       debug_pimv6_events_cmd,
       "[no] debug pimv6 events",
       NO_STR
       DEBUG_STR
       DEBUG_PIMV6_STR
       DEBUG_PIMV6_EVENTS_STR)
{
	if (!no)
		PIM_DO_DEBUG_PIM_EVENTS;
	else
		PIM_DONT_DEBUG_PIM_EVENTS;
	return CMD_SUCCESS;
}

DEFPY (debug_pimv6_packets,
       debug_pimv6_packets_cmd,
       "[no] debug pimv6 packets [<hello$hello|joins$joins|register$registers>]",
       NO_STR
       DEBUG_STR
       DEBUG_PIMV6_STR
       DEBUG_PIMV6_PACKETS_STR
       DEBUG_PIMV6_HELLO_PACKETS_STR
       DEBUG_PIMV6_J_P_PACKETS_STR
       DEBUG_PIMV6_PIM_REG_PACKETS_STR)
{
	if (!no)
		return pim_debug_pim_packets_cmd(hello, joins, registers, vty);
	else
		return pim_no_debug_pim_packets_cmd(hello, joins, registers,
						    vty);
}

DEFPY (debug_pimv6_packetdump_send,
       debug_pimv6_packetdump_send_cmd,
       "[no] debug pimv6 packet-dump send",
       NO_STR
       DEBUG_STR
       DEBUG_PIMV6_STR
       DEBUG_PIMV6_PACKETDUMP_STR
       DEBUG_PIMV6_PACKETDUMP_SEND_STR)
{
	if (!no)
		PIM_DO_DEBUG_PIM_PACKETDUMP_SEND;
	else
		PIM_DONT_DEBUG_PIM_PACKETDUMP_SEND;
	return CMD_SUCCESS;
}

DEFPY (debug_pimv6_packetdump_recv,
       debug_pimv6_packetdump_recv_cmd,
       "[no] debug pimv6 packet-dump receive",
       NO_STR
       DEBUG_STR
       DEBUG_PIMV6_STR
       DEBUG_PIMV6_PACKETDUMP_STR
       DEBUG_PIMV6_PACKETDUMP_RECV_STR)
{
	if (!no)
		PIM_DO_DEBUG_PIM_PACKETDUMP_RECV;
	else
		PIM_DONT_DEBUG_PIM_PACKETDUMP_RECV;
	return CMD_SUCCESS;
}

DEFPY (debug_pimv6_trace,
       debug_pimv6_trace_cmd,
       "[no] debug pimv6 trace",
       NO_STR
       DEBUG_STR
       DEBUG_PIMV6_STR
       DEBUG_PIMV6_TRACE_STR)
{
	if (!no)
		PIM_DO_DEBUG_PIM_TRACE;
	else
		PIM_DONT_DEBUG_PIM_TRACE;
	return CMD_SUCCESS;
}

DEFPY (debug_pimv6_trace_detail,
       debug_pimv6_trace_detail_cmd,
       "[no] debug pimv6 trace detail",
       NO_STR
       DEBUG_STR
       DEBUG_PIMV6_STR
       DEBUG_PIMV6_TRACE_STR
       "Detailed Information\n")
{
	if (!no)
		PIM_DO_DEBUG_PIM_TRACE_DETAIL;
	else
		PIM_DONT_DEBUG_PIM_TRACE_DETAIL;
	return CMD_SUCCESS;
}

DEFPY (debug_pimv6_zebra,
       debug_pimv6_zebra_cmd,
       "[no] debug pimv6 zebra",
       NO_STR
       DEBUG_STR
       DEBUG_PIMV6_STR
       DEBUG_PIMV6_ZEBRA_STR)
{
	if (!no)
		PIM_DO_DEBUG_ZEBRA;
	else
		PIM_DONT_DEBUG_ZEBRA;
	return CMD_SUCCESS;
}

void pim_cmd_init(void)
{
	if_cmd_init(pim_interface_config_write);

	install_node(&debug_node);

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
	install_element(CONFIG_NODE, &ipv6_ssmpingd_cmd);
	install_element(VRF_NODE, &ipv6_ssmpingd_cmd);
	install_element(CONFIG_NODE, &no_ipv6_ssmpingd_cmd);
	install_element(VRF_NODE, &no_ipv6_ssmpingd_cmd);
	install_element(INTERFACE_NODE, &interface_ipv6_mld_cmd);
	install_element(INTERFACE_NODE, &interface_no_ipv6_mld_cmd);
	install_element(INTERFACE_NODE, &interface_ipv6_mld_join_cmd);
	install_element(INTERFACE_NODE, &interface_no_ipv6_mld_join_cmd);
	install_element(INTERFACE_NODE, &interface_ipv6_mld_version_cmd);
	install_element(INTERFACE_NODE, &interface_no_ipv6_mld_version_cmd);
	install_element(INTERFACE_NODE, &interface_ipv6_mld_query_interval_cmd);
	install_element(INTERFACE_NODE,
			&interface_no_ipv6_mld_query_interval_cmd);
	install_element(CONFIG_NODE, &ipv6_mld_group_watermark_cmd);
	install_element(VRF_NODE, &ipv6_mld_group_watermark_cmd);
	install_element(CONFIG_NODE, &no_ipv6_mld_group_watermark_cmd);
	install_element(VRF_NODE, &no_ipv6_mld_group_watermark_cmd);
	install_element(INTERFACE_NODE,
			&interface_ipv6_mld_query_max_response_time_cmd);
	install_element(INTERFACE_NODE,
			&interface_no_ipv6_mld_query_max_response_time_cmd);
	install_element(INTERFACE_NODE,
			&interface_ipv6_mld_last_member_query_count_cmd);
	install_element(INTERFACE_NODE,
			&interface_no_ipv6_mld_last_member_query_count_cmd);
	install_element(INTERFACE_NODE,
			&interface_ipv6_mld_last_member_query_interval_cmd);
	install_element(INTERFACE_NODE,
			&interface_no_ipv6_mld_last_member_query_interval_cmd);

	install_element(VIEW_NODE, &show_ipv6_pim_rp_cmd);
	install_element(VIEW_NODE, &show_ipv6_pim_rp_vrf_all_cmd);
	install_element(VIEW_NODE, &show_ipv6_pim_rpf_cmd);
	install_element(VIEW_NODE, &show_ipv6_pim_rpf_vrf_all_cmd);
	install_element(VIEW_NODE, &show_ipv6_pim_secondary_cmd);
	install_element(VIEW_NODE, &show_ipv6_pim_statistics_cmd);
	install_element(VIEW_NODE, &show_ipv6_pim_upstream_cmd);
	install_element(VIEW_NODE, &show_ipv6_pim_upstream_vrf_all_cmd);
	install_element(VIEW_NODE, &show_ipv6_pim_upstream_join_desired_cmd);
	install_element(VIEW_NODE, &show_ipv6_pim_upstream_rpf_cmd);
	install_element(VIEW_NODE, &show_ipv6_pim_state_cmd);
	install_element(VIEW_NODE, &show_ipv6_pim_state_vrf_all_cmd);
	install_element(VIEW_NODE, &show_ipv6_pim_channel_cmd);
	install_element(VIEW_NODE, &show_ipv6_pim_interface_cmd);
	install_element(VIEW_NODE, &show_ipv6_pim_interface_vrf_all_cmd);
	install_element(VIEW_NODE, &show_ipv6_pim_join_cmd);
	install_element(VIEW_NODE, &show_ipv6_pim_join_vrf_all_cmd);
	install_element(VIEW_NODE, &show_ipv6_pim_jp_agg_cmd);
	install_element(VIEW_NODE, &show_ipv6_pim_local_membership_cmd);
	install_element(VIEW_NODE, &show_ipv6_pim_neighbor_cmd);
	install_element(VIEW_NODE, &show_ipv6_pim_neighbor_vrf_all_cmd);
	install_element(VIEW_NODE, &show_ipv6_pim_nexthop_cmd);
	install_element(VIEW_NODE, &show_ipv6_pim_nexthop_lookup_cmd);
	install_element(VIEW_NODE, &show_ipv6_multicast_cmd);
	install_element(VIEW_NODE, &show_ipv6_multicast_vrf_all_cmd);
	install_element(VIEW_NODE, &show_ipv6_multicast_count_cmd);
	install_element(VIEW_NODE, &show_ipv6_multicast_count_vrf_all_cmd);
	install_element(VIEW_NODE, &show_ipv6_mroute_cmd);
	install_element(VIEW_NODE, &show_ipv6_mroute_vrf_all_cmd);
	install_element(VIEW_NODE, &show_ipv6_mroute_count_cmd);
	install_element(VIEW_NODE, &show_ipv6_mroute_count_vrf_all_cmd);
	install_element(VIEW_NODE, &show_ipv6_mroute_summary_cmd);
	install_element(VIEW_NODE, &show_ipv6_mroute_summary_vrf_all_cmd);

	install_element(ENABLE_NODE, &clear_ipv6_pim_statistics_cmd);
	install_element(ENABLE_NODE, &clear_ipv6_mroute_cmd);
	install_element(ENABLE_NODE, &clear_ipv6_pim_oil_cmd);
	install_element(ENABLE_NODE, &clear_ipv6_mroute_count_cmd);
	install_element(ENABLE_NODE, &debug_pimv6_cmd);
	install_element(ENABLE_NODE, &debug_pimv6_nht_cmd);
	install_element(ENABLE_NODE, &debug_pimv6_nht_det_cmd);
	install_element(ENABLE_NODE, &debug_pimv6_events_cmd);
	install_element(ENABLE_NODE, &debug_pimv6_packets_cmd);
	install_element(ENABLE_NODE, &debug_pimv6_packetdump_send_cmd);
	install_element(ENABLE_NODE, &debug_pimv6_packetdump_recv_cmd);
	install_element(ENABLE_NODE, &debug_pimv6_trace_cmd);
	install_element(ENABLE_NODE, &debug_pimv6_trace_detail_cmd);
	install_element(ENABLE_NODE, &debug_pimv6_zebra_cmd);

	install_element(CONFIG_NODE, &debug_pimv6_cmd);
	install_element(CONFIG_NODE, &debug_pimv6_nht_cmd);
	install_element(CONFIG_NODE, &debug_pimv6_nht_det_cmd);
	install_element(CONFIG_NODE, &debug_pimv6_events_cmd);
	install_element(CONFIG_NODE, &debug_pimv6_packets_cmd);
	install_element(CONFIG_NODE, &debug_pimv6_packetdump_send_cmd);
	install_element(CONFIG_NODE, &debug_pimv6_packetdump_recv_cmd);
	install_element(CONFIG_NODE, &debug_pimv6_trace_cmd);
	install_element(CONFIG_NODE, &debug_pimv6_trace_detail_cmd);
	install_element(CONFIG_NODE, &debug_pimv6_zebra_cmd);
}
