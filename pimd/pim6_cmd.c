// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for IPv6 FRR
 * Copyright (C) 2022  Vmware, Inc.
 *		       Mobashshera Rasool <mrasool@vmware.com>
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

#include "pimd/pim6_cmd_clippy.c"

static struct cmd_node debug_node = {
	.name = "debug",
	.node = DEBUG_NODE,
	.prompt = "",
	.config_write = pim_debug_config_write,
};

DEFPY_NOSH (router_pim6,
            router_pim6_cmd,
            "router pim6 [vrf NAME]",
            "Enable a routing process\n"
            "Start PIM6 configuration\n"
            VRF_CMD_HELP_STR)
{
	char xpath[XPATH_MAXLEN];
	const char *vrf_name;

	if (vrf)
		vrf_name = vrf;
	else
		vrf_name = VRF_DEFAULT_NAME;

	snprintf(xpath, sizeof(xpath), FRR_PIM_VRF_XPATH, "frr-pim:pimd", "pim",
		 vrf_name, FRR_PIM_AF_XPATH_VAL);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	if (nb_cli_apply_changes_clear_pending(vty, NULL) != CMD_SUCCESS)
		return CMD_WARNING_CONFIG_FAILED;

	VTY_PUSH_XPATH(PIM6_NODE, xpath);

	return CMD_SUCCESS;
}

DEFPY (no_router_pim6,
       no_router_pim6_cmd,
       "no router pim6 [vrf NAME]",
       NO_STR
       "Enable a routing process\n"
       "Start PIM6 configuration\n"
       VRF_CMD_HELP_STR)
{
	char xpath[XPATH_MAXLEN];
	const char *vrf_name;

	if (vrf)
		vrf_name = vrf;
	else
		vrf_name = VRF_DEFAULT_NAME;

	snprintf(xpath, sizeof(xpath), FRR_PIM_VRF_XPATH, "frr-pim:pimd", "pim",
		 vrf_name, FRR_PIM_AF_XPATH_VAL);

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY (pim6_joinprune_time,
       pim6_joinprune_time_cmd,
       "join-prune-interval (1-65535)$jpi",
       "Join Prune Send Interval\n"
       "Seconds\n")
{
	return pim_process_join_prune_cmd(vty, jpi_str);
}
DEFPY_ATTR(ipv6_joinprune_time,
           ipv6_pim_joinprune_time_cmd,
           "ipv6 pim join-prune-interval (1-65535)$jpi",
           IPV6_STR PIM_STR
           "Join Prune Send Interval\n"
           "Seconds\n",
           CMD_ATTR_HIDDEN | CMD_ATTR_DEPRECATED)
{
	int ret;
	const char *vrfname;
	char xpath[XPATH_MAXLEN];
	int orig_node = -1;

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname) {
		snprintf(xpath, sizeof(xpath), FRR_PIM_VRF_XPATH,
			 "frr-pim:pimd", "pim", vrfname, FRR_PIM_AF_XPATH_VAL);
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
		if (nb_cli_apply_changes_clear_pending(vty, NULL) ==
		    CMD_SUCCESS) {
			orig_node = vty->node;
			VTY_PUSH_XPATH(PIM6_NODE, xpath);
		} else {
			return CMD_WARNING_CONFIG_FAILED;
		}
	} else {
		vty_out(vty, "%% Failed to determine vrf name\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ret = pim_process_join_prune_cmd(vty, jpi_str);

	if (orig_node != -1) {
		vty->node = orig_node;
		vty->xpath_index--;
	}

	return ret;
}

DEFPY (no_pim6_joinprune_time,
       no_pim6_joinprune_time_cmd,
       "no join-prune-interval [(1-65535)]",
       NO_STR
       "Join Prune Send Interval\n"
       IGNORED_IN_NO_STR)
{
	return pim_process_no_join_prune_cmd(vty);
}
DEFPY_ATTR(no_ipv6_pim_joinprune_time,
           no_ipv6_pim_joinprune_time_cmd,
           "no ipv6 pim join-prune-interval [(1-65535)]",
           NO_STR
           IPV6_STR
           PIM_STR
           "Join Prune Send Interval\n"
           IGNORED_IN_NO_STR,
           CMD_ATTR_HIDDEN | CMD_ATTR_DEPRECATED)
{
	int ret;
	const char *vrfname;
	char xpath[XPATH_MAXLEN];
	int orig_node = -1;

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname) {
		snprintf(xpath, sizeof(xpath), FRR_PIM_VRF_XPATH,
			 "frr-pim:pimd", "pim", vrfname, FRR_PIM_AF_XPATH_VAL);
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
		if (nb_cli_apply_changes_clear_pending(vty, NULL) ==
		    CMD_SUCCESS) {
			orig_node = vty->node;
			VTY_PUSH_XPATH(PIM6_NODE, xpath);
		} else {
			return CMD_WARNING_CONFIG_FAILED;
		}
	} else {
		vty_out(vty, "%% Failed to determine vrf name\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ret = pim_process_no_join_prune_cmd(vty);

	if (orig_node != -1) {
		vty->node = orig_node;
		vty->xpath_index--;
	}

	return ret;
}

DEFPY (pim6_spt_switchover_infinity,
       pim6_spt_switchover_infinity_cmd,
       "spt-switchover infinity-and-beyond",
       "SPT-Switchover\n"
       "Never switch to SPT Tree\n")
{
	return pim_process_spt_switchover_infinity_cmd(vty);
}
DEFPY_ATTR(ipv6_spt_switchover_infinity,
           ipv6_pim_spt_switchover_infinity_cmd,
           "ipv6 pim spt-switchover infinity-and-beyond",
           IPV6_STR
           PIM_STR
           "SPT-Switchover\n"
           "Never switch to SPT Tree\n",
           CMD_ATTR_HIDDEN | CMD_ATTR_DEPRECATED)
{
	int ret;
	const char *vrfname;
	char xpath[XPATH_MAXLEN];
	int orig_node = -1;

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname) {
		snprintf(xpath, sizeof(xpath), FRR_PIM_VRF_XPATH,
			 "frr-pim:pimd", "pim", vrfname, FRR_PIM_AF_XPATH_VAL);
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
		if (nb_cli_apply_changes_clear_pending(vty, NULL) ==
		    CMD_SUCCESS) {
			orig_node = vty->node;
			VTY_PUSH_XPATH(PIM6_NODE, xpath);
		} else {
			return CMD_WARNING_CONFIG_FAILED;
		}
	} else {
		vty_out(vty, "%% Failed to determine vrf name\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ret = pim_process_spt_switchover_infinity_cmd(vty);

	if (orig_node != -1) {
		vty->node = orig_node;
		vty->xpath_index--;
	}

	return ret;
}

DEFPY (pim6_spt_switchover_infinity_plist,
       pim6_spt_switchover_infinity_plist_cmd,
       "spt-switchover infinity-and-beyond prefix-list PREFIXLIST6_NAME$plist",
       "SPT-Switchover\n"
       "Never switch to SPT Tree\n"
       "Prefix-List to control which groups to switch\n"
       "Prefix-List name\n")
{
	return pim_process_spt_switchover_prefixlist_cmd(vty, plist);
}
DEFPY_ATTR(ipv6_spt_switchover_infinity_plist,
           ipv6_pim_spt_switchover_infinity_plist_cmd,
           "ipv6 pim spt-switchover infinity-and-beyond prefix-list PREFIXLIST6_NAME$plist",
           IPV6_STR
           PIM_STR
           "SPT-Switchover\n"
           "Never switch to SPT Tree\n"
           "Prefix-List to control which groups to switch\n"
           "Prefix-List name\n",
           CMD_ATTR_HIDDEN | CMD_ATTR_DEPRECATED)
{
	int ret;
	const char *vrfname;
	char xpath[XPATH_MAXLEN];
	int orig_node = -1;

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname) {
		snprintf(xpath, sizeof(xpath), FRR_PIM_VRF_XPATH,
			 "frr-pim:pimd", "pim", vrfname, FRR_PIM_AF_XPATH_VAL);
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
		if (nb_cli_apply_changes_clear_pending(vty, NULL) ==
		    CMD_SUCCESS) {
			orig_node = vty->node;
			VTY_PUSH_XPATH(PIM6_NODE, xpath);
		} else {
			return CMD_WARNING_CONFIG_FAILED;
		}
	} else {
		vty_out(vty, "%% Failed to determine vrf name\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ret = pim_process_spt_switchover_prefixlist_cmd(vty, plist);

	if (orig_node != -1) {
		vty->node = orig_node;
		vty->xpath_index--;
	}

	return ret;
}

DEFPY (no_pim6_spt_switchover_infinity,
       no_pim6_spt_switchover_infinity_cmd,
       "no spt-switchover infinity-and-beyond",
       NO_STR
       "SPT_Switchover\n"
       "Never switch to SPT Tree\n")
{
	return pim_process_no_spt_switchover_cmd(vty);
}
DEFPY_ATTR(no_ipv6_pim_spt_switchover_infinity,
           no_ipv6_pim_spt_switchover_infinity_cmd,
           "no ipv6 pim spt-switchover infinity-and-beyond",
           NO_STR
           IPV6_STR
           PIM_STR
           "SPT_Switchover\n"
           "Never switch to SPT Tree\n",
           CMD_ATTR_HIDDEN | CMD_ATTR_DEPRECATED)
{
	int ret;
	const char *vrfname;
	char xpath[XPATH_MAXLEN];
	int orig_node = -1;

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname) {
		snprintf(xpath, sizeof(xpath), FRR_PIM_VRF_XPATH,
			 "frr-pim:pimd", "pim", vrfname, FRR_PIM_AF_XPATH_VAL);
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
		if (nb_cli_apply_changes_clear_pending(vty, NULL) ==
		    CMD_SUCCESS) {
			orig_node = vty->node;
			VTY_PUSH_XPATH(PIM6_NODE, xpath);
		} else {
			return CMD_WARNING_CONFIG_FAILED;
		}
	} else {
		vty_out(vty, "%% Failed to determine vrf name\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ret = pim_process_no_spt_switchover_cmd(vty);

	if (orig_node != -1) {
		vty->node = orig_node;
		vty->xpath_index--;
	}

	return ret;
}

DEFPY (no_pim6_spt_switchover_infinity_plist,
       no_pim6_spt_switchover_infinity_plist_cmd,
       "no spt-switchover infinity-and-beyond prefix-list PREFIXLIST6_NAME",
       NO_STR
       "SPT_Switchover\n"
       "Never switch to SPT Tree\n"
       "Prefix-List to control which groups to switch\n"
       "Prefix-List name\n")
{
	return pim_process_no_spt_switchover_cmd(vty);
}
DEFPY_ATTR(no_ipv6_pim_spt_switchover_infinity_plist,
           no_ipv6_pim_spt_switchover_infinity_plist_cmd,
           "no ipv6 pim spt-switchover infinity-and-beyond prefix-list PREFIXLIST6_NAME",
           NO_STR
           IPV6_STR
           PIM_STR
           "SPT_Switchover\n"
           "Never switch to SPT Tree\n"
           "Prefix-List to control which groups to switch\n"
           "Prefix-List name\n",
           CMD_ATTR_HIDDEN | CMD_ATTR_DEPRECATED)
{
	int ret;
	const char *vrfname;
	char xpath[XPATH_MAXLEN];
	int orig_node = -1;

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname) {
		snprintf(xpath, sizeof(xpath), FRR_PIM_VRF_XPATH,
			 "frr-pim:pimd", "pim", vrfname, FRR_PIM_AF_XPATH_VAL);
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
		if (nb_cli_apply_changes_clear_pending(vty, NULL) ==
		    CMD_SUCCESS) {
			orig_node = vty->node;
			VTY_PUSH_XPATH(PIM6_NODE, xpath);
		} else {
			return CMD_WARNING_CONFIG_FAILED;
		}
	} else {
		vty_out(vty, "%% Failed to determine vrf name\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ret = pim_process_no_spt_switchover_cmd(vty);

	if (orig_node != -1) {
		vty->node = orig_node;
		vty->xpath_index--;
	}

	return ret;
}

DEFPY (pim6_packets,
       pim6_packets_cmd,
       "packets (1-255)",
       "packets to process at one time per fd\n"
       "Number of packets\n")
{
	return pim_process_pim_packet_cmd(vty, packets_str);
}
DEFPY_ATTR(ipv6_pim_packets,
           ipv6_pim_packets_cmd,
           "ipv6 pim packets (1-255)",
           IPV6_STR
           PIM_STR
           "packets to process at one time per fd\n"
           "Number of packets\n",
           CMD_ATTR_HIDDEN | CMD_ATTR_DEPRECATED)
{
	int ret;
	const char *vrfname;
	char xpath[XPATH_MAXLEN];
	int orig_node = -1;

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname) {
		snprintf(xpath, sizeof(xpath), FRR_PIM_VRF_XPATH,
			 "frr-pim:pimd", "pim", vrfname, FRR_PIM_AF_XPATH_VAL);
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
		if (nb_cli_apply_changes_clear_pending(vty, NULL) ==
		    CMD_SUCCESS) {
			orig_node = vty->node;
			VTY_PUSH_XPATH(PIM6_NODE, xpath);
		} else {
			return CMD_WARNING_CONFIG_FAILED;
		}
	} else {
		vty_out(vty, "%% Failed to determine vrf name\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ret = pim_process_pim_packet_cmd(vty, packets_str);

	if (orig_node != -1) {
		vty->node = orig_node;
		vty->xpath_index--;
	}

	return ret;
}

DEFPY (no_pim6_packets,
       no_pim6_packets_cmd,
       "no packets [(1-255)]",
       NO_STR
       "packets to process at one time per fd\n"
       IGNORED_IN_NO_STR)
{
	return pim_process_no_pim_packet_cmd(vty);
}
DEFPY_ATTR(no_ipv6_pim_packets,
           no_ipv6_pim_packets_cmd,
           "no ipv6 pim packets [(1-255)]",
           NO_STR
           IPV6_STR
           PIM_STR
           "packets to process at one time per fd\n"
           IGNORED_IN_NO_STR,
           CMD_ATTR_HIDDEN | CMD_ATTR_DEPRECATED)
{
	int ret;
	const char *vrfname;
	char xpath[XPATH_MAXLEN];
	int orig_node = -1;

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname) {
		snprintf(xpath, sizeof(xpath), FRR_PIM_VRF_XPATH,
			 "frr-pim:pimd", "pim", vrfname, FRR_PIM_AF_XPATH_VAL);
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
		if (nb_cli_apply_changes_clear_pending(vty, NULL) ==
		    CMD_SUCCESS) {
			orig_node = vty->node;
			VTY_PUSH_XPATH(PIM6_NODE, xpath);
		} else {
			return CMD_WARNING_CONFIG_FAILED;
		}
	} else {
		vty_out(vty, "%% Failed to determine vrf name\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ret = pim_process_no_pim_packet_cmd(vty);

	if (orig_node != -1) {
		vty->node = orig_node;
		vty->xpath_index--;
	}

	return ret;
}

DEFPY (pim6_keep_alive,
       pim6_keep_alive_cmd,
       "keep-alive-timer (1-65535)$kat",
       "Keep alive Timer\n"
       "Seconds\n")
{
	return pim_process_keepalivetimer_cmd(vty, kat_str);
}
DEFPY_ATTR(ipv6_pim_keep_alive,
           ipv6_pim_keep_alive_cmd,
           "ipv6 pim keep-alive-timer (1-65535)$kat",
           IPV6_STR
           PIM_STR
           "Keep alive Timer\n"
           "Seconds\n",
           CMD_ATTR_HIDDEN | CMD_ATTR_DEPRECATED)
{
	int ret;
	const char *vrfname;
	char xpath[XPATH_MAXLEN];
	int orig_node = -1;

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname) {
		snprintf(xpath, sizeof(xpath), FRR_PIM_VRF_XPATH,
			 "frr-pim:pimd", "pim", vrfname, FRR_PIM_AF_XPATH_VAL);
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
		if (nb_cli_apply_changes_clear_pending(vty, NULL) ==
		    CMD_SUCCESS) {
			orig_node = vty->node;
			VTY_PUSH_XPATH(PIM6_NODE, xpath);
		} else {
			return CMD_WARNING_CONFIG_FAILED;
		}
	} else {
		vty_out(vty, "%% Failed to determine vrf name\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ret = pim_process_keepalivetimer_cmd(vty, kat_str);

	if (orig_node != -1) {
		vty->node = orig_node;
		vty->xpath_index--;
	}

	return ret;
}

DEFPY (no_pim6_keep_alive,
       no_pim6_keep_alive_cmd,
       "no keep-alive-timer [(1-65535)]",
       NO_STR
       "Keep alive Timer\n"
       IGNORED_IN_NO_STR)
{
	return pim_process_no_keepalivetimer_cmd(vty);
}
DEFPY_ATTR(no_ipv6_pim_keep_alive,
           no_ipv6_pim_keep_alive_cmd,
           "no ipv6 pim keep-alive-timer [(1-65535)]",
           NO_STR
           IPV6_STR
           PIM_STR
           "Keep alive Timer\n"
           IGNORED_IN_NO_STR,
           CMD_ATTR_HIDDEN | CMD_ATTR_DEPRECATED)
{
	int ret;
	const char *vrfname;
	char xpath[XPATH_MAXLEN];
	int orig_node = -1;

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname) {
		snprintf(xpath, sizeof(xpath), FRR_PIM_VRF_XPATH,
			 "frr-pim:pimd", "pim", vrfname, FRR_PIM_AF_XPATH_VAL);
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
		if (nb_cli_apply_changes_clear_pending(vty, NULL) ==
		    CMD_SUCCESS) {
			orig_node = vty->node;
			VTY_PUSH_XPATH(PIM6_NODE, xpath);
		} else {
			return CMD_WARNING_CONFIG_FAILED;
		}
	} else {
		vty_out(vty, "%% Failed to determine vrf name\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ret = pim_process_no_keepalivetimer_cmd(vty);

	if (orig_node != -1) {
		vty->node = orig_node;
		vty->xpath_index--;
	}

	return ret;
}

DEFPY (pim6_rp_keep_alive,
       pim6_rp_keep_alive_cmd,
       "rp keep-alive-timer (1-65535)$kat",
       "Rendezvous Point\n"
       "Keep alive Timer\n"
       "Seconds\n")
{
	return pim_process_rp_kat_cmd(vty, kat_str);
}
DEFPY_ATTR(ipv6_pim_rp_keep_alive,
           ipv6_pim_rp_keep_alive_cmd,
           "ipv6 pim rp keep-alive-timer (1-65535)$kat",
           IPV6_STR
           PIM_STR
           "Rendezvous Point\n"
           "Keep alive Timer\n"
           "Seconds\n",
           CMD_ATTR_HIDDEN | CMD_ATTR_DEPRECATED)
{
	int ret;
	const char *vrfname;
	char xpath[XPATH_MAXLEN];
	int orig_node = -1;

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname) {
		snprintf(xpath, sizeof(xpath), FRR_PIM_VRF_XPATH,
			 "frr-pim:pimd", "pim", vrfname, FRR_PIM_AF_XPATH_VAL);
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
		if (nb_cli_apply_changes_clear_pending(vty, NULL) ==
		    CMD_SUCCESS) {
			orig_node = vty->node;
			VTY_PUSH_XPATH(PIM6_NODE, xpath);
		} else {
			return CMD_WARNING_CONFIG_FAILED;
		}
	} else {
		vty_out(vty, "%% Failed to determine vrf name\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ret = pim_process_rp_kat_cmd(vty, kat_str);

	if (orig_node != -1) {
		vty->node = orig_node;
		vty->xpath_index--;
	}

	return ret;
}

DEFPY (no_pim6_rp_keep_alive,
       no_pim6_rp_keep_alive_cmd,
       "no rp keep-alive-timer [(1-65535)]",
       NO_STR
       "Rendezvous Point\n"
       "Keep alive Timer\n"
       IGNORED_IN_NO_STR)
{
	return pim_process_no_rp_kat_cmd(vty);
}
DEFPY_ATTR(no_ipv6_pim_rp_keep_alive,
           no_ipv6_pim_rp_keep_alive_cmd,
           "no ipv6 pim rp keep-alive-timer [(1-65535)]",
           NO_STR
           IPV6_STR
           PIM_STR
           "Rendezvous Point\n"
           "Keep alive Timer\n"
           IGNORED_IN_NO_STR,
           CMD_ATTR_HIDDEN | CMD_ATTR_DEPRECATED)
{
	int ret;
	const char *vrfname;
	char xpath[XPATH_MAXLEN];
	int orig_node = -1;

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname) {
		snprintf(xpath, sizeof(xpath), FRR_PIM_VRF_XPATH,
			 "frr-pim:pimd", "pim", vrfname, FRR_PIM_AF_XPATH_VAL);
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
		if (nb_cli_apply_changes_clear_pending(vty, NULL) ==
		    CMD_SUCCESS) {
			orig_node = vty->node;
			VTY_PUSH_XPATH(PIM6_NODE, xpath);
		} else {
			return CMD_WARNING_CONFIG_FAILED;
		}
	} else {
		vty_out(vty, "%% Failed to determine vrf name\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ret = pim_process_no_rp_kat_cmd(vty);

	if (orig_node != -1) {
		vty->node = orig_node;
		vty->xpath_index--;
	}

	return ret;
}

DEFPY (pim6_register_suppress,
       pim6_register_suppress_cmd,
       "register-suppress-time (1-65535)$rst",
       "Register Suppress Timer\n"
       "Seconds\n")
{
	return pim_process_register_suppress_cmd(vty, rst_str);
}
DEFPY_ATTR(ipv6_pim_register_suppress,
           ipv6_pim_register_suppress_cmd,
           "ipv6 pim register-suppress-time (1-65535)$rst",
           IPV6_STR
           PIM_STR
           "Register Suppress Timer\n"
           "Seconds\n",
           CMD_ATTR_HIDDEN | CMD_ATTR_DEPRECATED)
{
	int ret;
	const char *vrfname;
	char xpath[XPATH_MAXLEN];
	int orig_node = -1;

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname) {
		snprintf(xpath, sizeof(xpath), FRR_PIM_VRF_XPATH,
			 "frr-pim:pimd", "pim", vrfname, FRR_PIM_AF_XPATH_VAL);
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
		if (nb_cli_apply_changes_clear_pending(vty, NULL) ==
		    CMD_SUCCESS) {
			orig_node = vty->node;
			VTY_PUSH_XPATH(PIM6_NODE, xpath);
		} else {
			return CMD_WARNING_CONFIG_FAILED;
		}
	} else {
		vty_out(vty, "%% Failed to determine vrf name\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ret = pim_process_register_suppress_cmd(vty, rst_str);

	if (orig_node != -1) {
		vty->node = orig_node;
		vty->xpath_index--;
	}

	return ret;
}

DEFPY (no_pim6_register_suppress,
       no_pim6_register_suppress_cmd,
       "no register-suppress-time [(1-65535)]",
       NO_STR
       "Register Suppress Timer\n"
       IGNORED_IN_NO_STR)
{
	return pim_process_no_register_suppress_cmd(vty);
}
DEFPY_ATTR(no_ipv6_pim_register_suppress,
           no_ipv6_pim_register_suppress_cmd,
           "no ipv6 pim register-suppress-time [(1-65535)]",
           NO_STR
           IPV6_STR
           PIM_STR
           "Register Suppress Timer\n"
           IGNORED_IN_NO_STR,
           CMD_ATTR_HIDDEN | CMD_ATTR_DEPRECATED)
{
	int ret;
	const char *vrfname;
	char xpath[XPATH_MAXLEN];
	int orig_node = -1;

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname) {
		snprintf(xpath, sizeof(xpath), FRR_PIM_VRF_XPATH,
			 "frr-pim:pimd", "pim", vrfname, FRR_PIM_AF_XPATH_VAL);
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
		if (nb_cli_apply_changes_clear_pending(vty, NULL) ==
		    CMD_SUCCESS) {
			orig_node = vty->node;
			VTY_PUSH_XPATH(PIM6_NODE, xpath);
		} else {
			return CMD_WARNING_CONFIG_FAILED;
		}
	} else {
		vty_out(vty, "%% Failed to determine vrf name\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ret = pim_process_no_register_suppress_cmd(vty);

	if (orig_node != -1) {
		vty->node = orig_node;
		vty->xpath_index--;
	}

	return ret;
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
       "ipv6 pim drpriority (0-4294967295)",
       IPV6_STR
       PIM_STR
       "Set the Designated Router Election Priority\n"
       "Value of the new DR Priority\n")
{
	return pim_process_ip_pim_drprio_cmd(vty, drpriority_str);
}

DEFPY (interface_no_ipv6_pim_drprio,
       interface_no_ipv6_pim_drprio_cmd,
       "no ipv6 pim drpriority [(0-4294967295)]",
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

DEFPY (pim6_rp,
       pim6_rp_cmd,
       "rp X:X::X:X$rp [X:X::X:X/M]$gp",
       "Rendezvous Point\n"
       "ipv6 address of RP\n"
       "Group Address range to cover\n")
{
	const char *group_str = (gp_str) ? gp_str : "FF00::0/8";

	return pim_process_rp_cmd(vty, rp_str, group_str);
}
DEFPY_ATTR(ipv6_pim_rp,
           ipv6_pim_rp_cmd,
           "ipv6 pim rp X:X::X:X$rp [X:X::X:X/M]$gp",
           IPV6_STR
           PIM_STR
           "Rendezvous Point\n"
           "ipv6 address of RP\n"
           "Group Address range to cover\n",
           CMD_ATTR_HIDDEN | CMD_ATTR_DEPRECATED)
{
	int ret;
	const char *group_str = (gp_str) ? gp_str : "FF00::0/8";
	const char *vrfname;
	char xpath[XPATH_MAXLEN];
	int orig_node = -1;

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname) {
		snprintf(xpath, sizeof(xpath), FRR_PIM_VRF_XPATH,
			 "frr-pim:pimd", "pim", vrfname, FRR_PIM_AF_XPATH_VAL);
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
		if (nb_cli_apply_changes_clear_pending(vty, NULL) ==
		    CMD_SUCCESS) {
			orig_node = vty->node;
			VTY_PUSH_XPATH(PIM6_NODE, xpath);
		} else {
			return CMD_WARNING_CONFIG_FAILED;
		}
	} else {
		vty_out(vty, "%% Failed to determine vrf name\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ret = pim_process_rp_cmd(vty, rp_str, group_str);

	if (orig_node != -1) {
		vty->node = orig_node;
		vty->xpath_index--;
	}

	return ret;
}

DEFPY (no_pim6_rp,
       no_pim6_rp_cmd,
       "no rp X:X::X:X$rp [X:X::X:X/M]$gp",
       NO_STR
       "Rendezvous Point\n"
       "ipv6 address of RP\n"
       "Group Address range to cover\n")
{
	const char *group_str = (gp_str) ? gp_str : "FF00::0/8";

	return pim_process_no_rp_cmd(vty, rp_str, group_str);
}
DEFPY_ATTR(no_ipv6_pim_rp,
           no_ipv6_pim_rp_cmd,
           "no ipv6 pim rp X:X::X:X$rp [X:X::X:X/M]$gp",
           NO_STR
           IPV6_STR
           PIM_STR
           "Rendezvous Point\n"
           "ipv6 address of RP\n"
           "Group Address range to cover\n",
           CMD_ATTR_HIDDEN | CMD_ATTR_DEPRECATED)
{
	int ret;
	const char *group_str = (gp_str) ? gp_str : "FF00::0/8";
	const char *vrfname;
	char xpath[XPATH_MAXLEN];
	int orig_node = -1;

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname) {
		snprintf(xpath, sizeof(xpath), FRR_PIM_VRF_XPATH,
			 "frr-pim:pimd", "pim", vrfname, FRR_PIM_AF_XPATH_VAL);
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
		if (nb_cli_apply_changes_clear_pending(vty, NULL) ==
		    CMD_SUCCESS) {
			orig_node = vty->node;
			VTY_PUSH_XPATH(PIM6_NODE, xpath);
		} else {
			return CMD_WARNING_CONFIG_FAILED;
		}
	} else {
		vty_out(vty, "%% Failed to determine vrf name\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ret = pim_process_no_rp_cmd(vty, rp_str, group_str);

	if (orig_node != -1) {
		vty->node = orig_node;
		vty->xpath_index--;
	}

	return ret;
}

DEFPY (pim6_rp_prefix_list,
       pim6_rp_prefix_list_cmd,
       "rp X:X::X:X$rp prefix-list PREFIXLIST6_NAME$plist",
       "Rendezvous Point\n"
       "ipv6 address of RP\n"
       "group prefix-list filter\n"
       "Name of a prefix-list\n")
{
	return pim_process_rp_plist_cmd(vty, rp_str, plist);
}
DEFPY_ATTR(ipv6_pim_rp_prefix_list,
           ipv6_pim_rp_prefix_list_cmd,
           "ipv6 pim rp X:X::X:X$rp prefix-list PREFIXLIST6_NAME$plist",
           IPV6_STR
           PIM_STR
           "Rendezvous Point\n"
           "ipv6 address of RP\n"
           "group prefix-list filter\n"
           "Name of a prefix-list\n",
           CMD_ATTR_HIDDEN | CMD_ATTR_DEPRECATED)
{
	int ret;
	const char *vrfname;
	char xpath[XPATH_MAXLEN];
	int orig_node = -1;

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname) {
		snprintf(xpath, sizeof(xpath), FRR_PIM_VRF_XPATH,
			 "frr-pim:pimd", "pim", vrfname, FRR_PIM_AF_XPATH_VAL);
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
		if (nb_cli_apply_changes_clear_pending(vty, NULL) ==
		    CMD_SUCCESS) {
			orig_node = vty->node;
			VTY_PUSH_XPATH(PIM6_NODE, xpath);
		} else {
			return CMD_WARNING_CONFIG_FAILED;
		}
	} else {
		vty_out(vty, "%% Failed to determine vrf name\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ret = pim_process_rp_plist_cmd(vty, rp_str, plist);

	if (orig_node != -1) {
		vty->node = orig_node;
		vty->xpath_index--;
	}

	return ret;
}

DEFPY (no_pim6_rp_prefix_list,
       no_pim6_rp_prefix_list_cmd,
       "no rp X:X::X:X$rp prefix-list PREFIXLIST6_NAME$plist",
       NO_STR
       "Rendezvous Point\n"
       "ipv6 address of RP\n"
       "group prefix-list filter\n"
       "Name of a prefix-list\n")
{
	return pim_process_no_rp_plist_cmd(vty, rp_str, plist);
}
DEFPY_ATTR(no_ipv6_pim_rp_prefix_list,
           no_ipv6_pim_rp_prefix_list_cmd,
           "no ipv6 pim rp X:X::X:X$rp prefix-list PREFIXLIST6_NAME$plist",
           NO_STR
           IPV6_STR
           PIM_STR
           "Rendezvous Point\n"
           "ipv6 address of RP\n"
           "group prefix-list filter\n"
           "Name of a prefix-list\n",
           CMD_ATTR_HIDDEN | CMD_ATTR_DEPRECATED)
{
	int ret;
	const char *vrfname;
	char xpath[XPATH_MAXLEN];
	int orig_node = -1;

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname) {
		snprintf(xpath, sizeof(xpath), FRR_PIM_VRF_XPATH,
			 "frr-pim:pimd", "pim", vrfname, FRR_PIM_AF_XPATH_VAL);
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
		if (nb_cli_apply_changes_clear_pending(vty, NULL) ==
		    CMD_SUCCESS) {
			orig_node = vty->node;
			VTY_PUSH_XPATH(PIM6_NODE, xpath);
		} else {
			return CMD_WARNING_CONFIG_FAILED;
		}
	} else {
		vty_out(vty, "%% Failed to determine vrf name\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ret = pim_process_no_rp_plist_cmd(vty, rp_str, plist);

	if (orig_node != -1) {
		vty->node = orig_node;
		vty->xpath_index--;
	}

	return ret;
}

DEFPY (ipv6_pim_bsm,
       ipv6_pim_bsm_cmd,
       "ipv6 pim bsm",
       IPV6_STR
       PIM_STR
       "Enable BSM support on the interface\n")
{
	return pim_process_bsm_cmd(vty);
}

DEFPY (no_ipv6_pim_bsm,
       no_ipv6_pim_bsm_cmd,
       "no ipv6 pim bsm",
       NO_STR
       IPV6_STR
       PIM_STR
       "Enable BSM support on the interface\n")
{
	return pim_process_no_bsm_cmd(vty);
}

DEFPY (ipv6_pim_ucast_bsm,
       ipv6_pim_ucast_bsm_cmd,
       "ipv6 pim unicast-bsm",
       IPV6_STR
       PIM_STR
       "Accept/Send unicast BSM on the interface\n")
{
	return pim_process_unicast_bsm_cmd(vty);
}

DEFPY (no_ipv6_pim_ucast_bsm,
       no_ipv6_pim_ucast_bsm_cmd,
       "no ipv6 pim unicast-bsm",
       NO_STR
       IPV6_STR
       PIM_STR
       "Accept/Send unicast BSM on the interface\n")
{
	return pim_process_no_unicast_bsm_cmd(vty);
}

DEFPY (pim6_bsr_candidate_bsr,
       pim6_bsr_candidate_bsr_cmd,
       "[no] bsr candidate-bsr [{priority (0-255)|source <address X:X::X:X|interface IFNAME|loopback$loopback|any$any>}]",
       NO_STR
       BSR_STR
       "Make this router a Candidate BSR\n"
       "BSR Priority (higher wins)\n"
       "BSR Priority (higher wins)\n"
       "Specify IP address for BSR operation\n"
       "Local address to use\n"
       "Local address to use\n"
       "Interface to pick address from\n"
       "Interface to pick address from\n"
       "Pick highest loopback address (default)\n"
       "Pick highest address from any interface\n")
{
	return pim_process_bsr_candidate_cmd(vty, FRR_PIM_CAND_BSR_XPATH, no,
					     false, any, ifname, address_str,
					     priority_str, NULL);
}

DEFPY (pim6_bsr_candidate_rp,
       pim6_bsr_candidate_rp_cmd,
       "[no] bsr candidate-rp [{priority (0-255)|interval (1-4294967295)|source <address X:X::X:X|interface IFNAME|loopback$loopback|any$any>}]",
       NO_STR
       "Bootstrap Router configuration\n"
       "Make this router a Candidate RP\n"
       "RP Priority (lower wins)\n"
       "RP Priority (lower wins)\n"
       "Advertisement interval (seconds)\n"
       "Advertisement interval (seconds)\n"
       "Specify IP address for RP operation\n"
       "Local address to use\n"
       "Local address to use\n"
       "Interface to pick address from\n"
       "Interface to pick address from\n"
       "Pick highest loopback address (default)\n"
       "Pick highest address from any interface\n")
{
	return pim_process_bsr_candidate_cmd(vty, FRR_PIM_CAND_RP_XPATH, no,
					     true, any, ifname, address_str,
					     priority_str, interval_str);
}

DEFPY (pim6_bsr_candidate_rp_group,
       pim6_bsr_candidate_rp_group_cmd,
       "[no] bsr candidate-rp group X:X::X:X/M",
       NO_STR
       "Bootstrap Router configuration\n"
       "Make this router a Candidate RP\n"
       "Configure groups to become candidate RP for\n"
       "Multicast group prefix\n")
{
	return pim_process_bsr_crp_grp_cmd(vty, group_str, no);
}

DEFPY (pim6_ssmpingd,
       pim6_ssmpingd_cmd,
       "ssmpingd [X:X::X:X]$source",
      CONF_SSMPINGD_STR
      "Source address\n")
{
	const char *src_str = (source_str) ? source_str : "::";

	return pim_process_ssmpingd_cmd(vty, NB_OP_CREATE, src_str);
}
DEFPY_ATTR(ipv6_ssmpingd,
           ipv6_ssmpingd_cmd,
           "ipv6 ssmpingd [X:X::X:X]$source",
           IPV6_STR
           CONF_SSMPINGD_STR
           "Source address\n",
           CMD_ATTR_HIDDEN | CMD_ATTR_DEPRECATED)
{
	int ret;
	const char *src_str = (source_str) ? source_str : "::";
	const char *vrfname;
	char xpath[XPATH_MAXLEN];
	int orig_node = -1;

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname) {
		snprintf(xpath, sizeof(xpath), FRR_PIM_VRF_XPATH,
			 "frr-pim:pimd", "pim", vrfname, FRR_PIM_AF_XPATH_VAL);
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
		if (nb_cli_apply_changes_clear_pending(vty, NULL) ==
		    CMD_SUCCESS) {
			orig_node = vty->node;
			VTY_PUSH_XPATH(PIM6_NODE, xpath);
		} else {
			return CMD_WARNING_CONFIG_FAILED;
		}
	} else {
		vty_out(vty, "%% Failed to determine vrf name\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ret = pim_process_ssmpingd_cmd(vty, NB_OP_CREATE, src_str);

	if (orig_node != -1) {
		vty->node = orig_node;
		vty->xpath_index--;
	}

	return ret;
}

DEFPY (no_pim6_ssmpingd,
       no_pim6_ssmpingd_cmd,
       "no ssmpingd [X:X::X:X]$source",
       NO_STR
       CONF_SSMPINGD_STR
       "Source address\n")
{
	const char *src_str = (source_str) ? source_str : "::";

	return pim_process_ssmpingd_cmd(vty, NB_OP_DESTROY, src_str);
}
DEFPY_ATTR(no_ipv6_ssmpingd,
           no_ipv6_ssmpingd_cmd,
           "no ipv6 ssmpingd [X:X::X:X]$source",
           NO_STR
           IPV6_STR
           CONF_SSMPINGD_STR
           "Source address\n",
           CMD_ATTR_HIDDEN | CMD_ATTR_DEPRECATED)
{
	int ret;
	const char *src_str = (source_str) ? source_str : "::";
	const char *vrfname;
	char xpath[XPATH_MAXLEN];
	int orig_node = -1;

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname) {
		snprintf(xpath, sizeof(xpath), FRR_PIM_VRF_XPATH,
			 "frr-pim:pimd", "pim", vrfname, FRR_PIM_AF_XPATH_VAL);
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
		if (nb_cli_apply_changes_clear_pending(vty, NULL) ==
		    CMD_SUCCESS) {
			orig_node = vty->node;
			VTY_PUSH_XPATH(PIM6_NODE, xpath);
		} else {
			return CMD_WARNING_CONFIG_FAILED;
		}
	} else {
		vty_out(vty, "%% Failed to determine vrf name\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ret = pim_process_ssmpingd_cmd(vty, NB_OP_DESTROY, src_str);

	if (orig_node != -1) {
		vty->node = orig_node;
		vty->xpath_index--;
	}

	return ret;
}

DEFPY_YANG_HIDDEN (interface_ipv6_mld_join,
                   interface_ipv6_mld_join_cmd,
                   "[no] ipv6 mld join X:X::X:X$grp [X:X::X:X]$src",
                   NO_STR
                   IPV6_STR
                   IFACE_MLD_STR
                   "MLD join multicast group\n"
                   "Multicast group address\n"
                   "Source address\n")
{
	nb_cli_enqueue_change(vty, ".", (!no ? NB_OP_CREATE : NB_OP_DESTROY),
			      NULL);
	return nb_cli_apply_changes(vty, FRR_GMP_JOIN_GROUP_XPATH,
				    "frr-routing:ipv6", grp_str,
				    (src_str ? src_str : "::"));
}
ALIAS (interface_ipv6_mld_join,
       interface_ipv6_mld_join_group_cmd,
       "[no] ipv6 mld join-group X:X::X:X$grp [X:X::X:X]$src",
       NO_STR
       IPV6_STR
       IFACE_MLD_STR
       "MLD join multicast group\n"
       "Multicast group address\n"
       "Source address\n");

DEFPY_YANG (interface_ipv6_mld_static_group,
            interface_ipv6_mld_static_group_cmd,
            "[no] ipv6 mld static-group X:X::X:X$grp [X:X::X:X]$src",
            NO_STR
            IPV6_STR
            IFACE_MLD_STR
            "Static multicast group\n"
            "Multicast group address\n"
            "Source address\n")
{
	nb_cli_enqueue_change(vty, ".", (!no ? NB_OP_CREATE : NB_OP_DESTROY),
			      NULL);
	return nb_cli_apply_changes(vty, FRR_GMP_STATIC_GROUP_XPATH,
				    "frr-routing:ipv6", grp_str,
				    (src_str ? src_str : "::"));
}

DEFPY (interface_no_ipv6_mld_static_group,
       interface_no_ipv6_mld_static_group_cmd,
       "no ipv6 mld static-group X:X::X:X$group [X:X::X:X$source]",
       NO_STR
       IPV6_STR
       IFACE_MLD_STR
       "Static multicast group\n"
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

	snprintf(xpath, sizeof(xpath), FRR_GMP_STATIC_GROUP_XPATH,
		 "frr-routing:ipv6", group_str, source_str);

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
	pim->gm_watermark_limit = limit;

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
	pim->gm_watermark_limit = 0;

	return CMD_SUCCESS;
}

DEFPY (interface_ipv6_mld_query_max_response_time,
       interface_ipv6_mld_query_max_response_time_cmd,
       "ipv6 mld query-max-response-time (1-65535)$qmrt",
       IPV6_STR
       IFACE_MLD_STR
       IFACE_MLD_QUERY_MAX_RESPONSE_TIME_STR
       "Query response value in deci-seconds\n")
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
	return pim_show_rp_helper(vrf, vty, group_str, (struct prefix *)group,
				  !!json);
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
	return pim_show_rp_vrf_all_helper(vty, group_str,
					  (struct prefix *)group, !!json);
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
	return pim_show_rpf_helper(vrf, vty, !!json);
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
	return pim_show_rpf_vrf_all_helper(vty, !!json);
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
	return pim_show_secondary_helper(vrf, vty);
}

DEFPY (show_ipv6_pim_bsr_cand_bsr,
       show_ipv6_pim_bsr_cand_bsr_cmd,
       "show ipv6 pim bsr candidate-bsr [vrf NAME$vrfname] [json$json]",
       SHOW_STR
       IPV6_STR
       PIM_STR
       BSR_STR
       "Current PIM router candidate BSR state\n"
       VRF_CMD_HELP_STR
       JSON_STR)
{
	int idx = 2;
	struct vrf *vrf = pim_cmd_lookup_vrf(vty, argv, argc, &idx, !!json);

	if (!vrf || !vrf->info)
		return CMD_WARNING;

	return pim_show_bsr_cand_bsr(vrf, vty, !!json);
}

DEFPY (show_ipv6_pim_bsr_cand_rp,
       show_ipv6_pim_bsr_cand_rp_cmd,
       "show ipv6 pim bsr candidate-rp [vrf VRF_NAME] [json$json]",
       SHOW_STR
       IPV6_STR
       PIM_STR
       BSR_STR
       "Current PIM router candidate RP state\n"
       VRF_CMD_HELP_STR
       JSON_STR)
{
	struct vrf *vrf = pim_cmd_lookup(vty, vrf_name);

	if (!vrf || !vrf->info)
		return CMD_WARNING;

	return pim_show_bsr_cand_rp(vrf, vty, !!json);
}

DEFPY (show_ipv6_pim_bsr_rpdb,
       show_ipv6_pim_bsr_rpdb_cmd,
       "show ipv6 pim bsr candidate-rp-database [vrf VRF_NAME] [json$json]",
       SHOW_STR
       IPV6_STR
       PIM_STR
       BSR_STR
       "Candidate RPs database on this router (if it is the BSR)\n"
       VRF_CMD_HELP_STR
       JSON_STR)
{
	struct vrf *vrf = pim_cmd_lookup(vty, vrf_name);

	if (!vrf || !vrf->info)
		return CMD_WARNING;

	struct pim_instance *pim = vrf->info;
	struct bsm_scope *scope = &pim->global_scope;

	return pim_crp_db_show(vty, scope, !!json);
}

DEFPY (show_ipv6_pim_bsr_groups,
       show_ipv6_pim_bsr_groups_cmd,
       "show ipv6 pim bsr groups [vrf VRF_NAME] [json$json]",
       SHOW_STR
       IPV6_STR
       PIM_STR
       "boot-strap router information\n"
       "Candidate RP groups\n"
       VRF_CMD_HELP_STR
       JSON_STR)
{
	struct vrf *vrf = pim_cmd_lookup(vty, vrf_name);

	if (!vrf || !vrf->info)
		return CMD_WARNING;

	struct pim_instance *pim = vrf->info;
	struct bsm_scope *scope = &pim->global_scope;

	return pim_crp_groups_show(vty, scope, !!json);
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
	return pim_show_statistics_helper(vrf, vty, word, !!json);
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
	return pim_show_upstream_helper(vrf, vty, s_or_g, g, !!json);
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
	return pim_show_upstream_vrf_all_helper(vty, !!json);
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
	return pim_show_upstream_join_desired_helper(vrf, vty, !!json);
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
	return pim_show_upstream_rpf_helper(vrf, vty, !!json);
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
	return pim_show_state_helper(vrf, vty, s_or_g_str, g_str, !!json);
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
	return pim_show_state_vrf_all_helper(vty, s_or_g_str, g_str, !!json);
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
	return pim_show_channel_cmd_helper(vrf, vty, !!json);
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
	return pim_show_interface_cmd_helper(vrf, vty, !!json, false,
					     interface);
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
	return pim_show_interface_vrf_all_cmd_helper(vty, !!json, false,
						     interface);
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
	return pim_show_join_cmd_helper(vrf, vty, s_or_g, g, json);
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
	return pim_show_join_vrf_all_cmd_helper(vty, json);
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
	return pim_show_jp_agg_list_cmd_helper(vrf, vty);
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
	return pim_show_membership_cmd_helper(vrf, vty, !!json);
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
	return pim_show_neighbors_cmd_helper(vrf, vty, json, interface);
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
	return pim_show_neighbors_vrf_all_cmd_helper(vty, json, interface);
}

DEFPY (show_ipv6_pim_nexthop,
       show_ipv6_pim_nexthop_cmd,
       "show ipv6 pim [vrf NAME] nexthop [json$json]",
       SHOW_STR
       IPV6_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "PIM cached nexthop rpf information\n"
       JSON_STR)
{
	return pim_show_nexthop_cmd_helper(vrf, vty, !!json);
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
	return pim_show_nexthop_lookup_cmd_helper(vrf, vty, source, group);
}

DEFPY (show_ipv6_multicast,
       show_ipv6_multicast_cmd,
       "show ipv6 multicast [vrf NAME]",
       SHOW_STR
       IPV6_STR
       "Multicast global information\n"
       VRF_CMD_HELP_STR)
{
	return pim_show_multicast_helper(vrf, vty);
}

DEFPY (show_ipv6_multicast_vrf_all,
       show_ipv6_multicast_vrf_all_cmd,
       "show ipv6 multicast vrf all",
       SHOW_STR
       IPV6_STR
       "Multicast global information\n"
       VRF_CMD_HELP_STR)
{
	return pim_show_multicast_vrf_all_helper(vty);
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
	return pim_show_multicast_count_helper(vrf, vty, !!json);
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
	return pim_show_multicast_count_vrf_all_helper(vty, !!json);
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
	return pim_show_mroute_helper(vrf, vty, s_or_g, g, !!fill, !!json);
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
	return pim_show_mroute_vrf_all_helper(vty, !!fill, !!json);
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
	return pim_show_mroute_count_helper(vrf, vty, !!json);
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
	return pim_show_mroute_count_vrf_all_helper(vty, !!json);
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
	return pim_show_mroute_summary_helper(vrf, vty, !!json);
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
	return pim_show_mroute_summary_vrf_all_helper(vty, !!json);
}

DEFPY (show_ipv6_pim_interface_traffic,
       show_ipv6_pim_interface_traffic_cmd,
       "show ipv6 pim [vrf NAME] interface traffic [WORD$if_name] [json$json]",
       SHOW_STR
       IPV6_STR
       PIM_STR
       VRF_CMD_HELP_STR
       "PIM interface information\n"
       "Protocol Packet counters\n"
       "Interface name\n"
       JSON_STR)
{
	return pim_show_interface_traffic_helper(vrf, if_name, vty, !!json);
}

DEFPY (show_ipv6_pim_bsr,
       show_ipv6_pim_bsr_cmd,
       "show ipv6 pim bsr [vrf NAME] [json$json]",
       SHOW_STR
       IPV6_STR
       PIM_STR
       "boot-strap router information\n"
       VRF_CMD_HELP_STR
       JSON_STR)
{
	return pim_show_bsr_helper(vrf, vty, !!json);
}

DEFPY (show_ipv6_pim_bsm_db,
       show_ipv6_pim_bsm_db_cmd,
       "show ipv6 pim bsm-database [vrf NAME] [json$json]",
       SHOW_STR
       IPV6_STR
       PIM_STR
       "PIM cached bsm packets information\n"
       VRF_CMD_HELP_STR
       JSON_STR)
{
	return pim_show_bsm_db_helper(vrf, vty, !!json);
}

DEFPY (show_ipv6_pim_bsrp,
       show_ipv6_pim_bsrp_cmd,
       "show ipv6 pim bsrp-info [vrf NAME] [json$json]",
       SHOW_STR
       IPV6_STR
       PIM_STR
       "PIM cached group-rp mappings information\n"
       VRF_CMD_HELP_STR
       JSON_STR)
{
	return pim_show_group_rp_mappings_info_helper(vrf, vty, !!json);
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

DEFPY (clear_ipv6_pim_interface_traffic,
       clear_ipv6_pim_interface_traffic_cmd,
       "clear ipv6 pim [vrf NAME] interface traffic",
       CLEAR_STR
       IPV6_STR
       CLEAR_IP_PIM_STR
       VRF_CMD_HELP_STR
       "Reset PIM interfaces\n"
       "Reset Protocol Packet counters\n")
{
	return clear_pim_interface_traffic(vrf, vty);
}

DEFPY (clear_ipv6_mroute,
       clear_ipv6_mroute_cmd,
       "clear ipv6 mroute [vrf NAME]$name",
       CLEAR_STR
       IPV6_STR
       MROUTE_STR
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

DEFPY (clear_ipv6_pim_interfaces,
       clear_ipv6_pim_interfaces_cmd,
       "clear ipv6 pim [vrf NAME] interfaces",
       CLEAR_STR
       IPV6_STR
       CLEAR_IP_PIM_STR
       VRF_CMD_HELP_STR
       "Reset PIM interfaces\n")
{
	struct vrf *v = pim_cmd_lookup(vty, vrf);

	if (!v)
		return CMD_WARNING;

	clear_pim_interfaces(v->info);

	return CMD_SUCCESS;
}

DEFPY (clear_ipv6_pim_bsr_db,
       clear_ipv6_pim_bsr_db_cmd,
       "clear ipv6 pim [vrf NAME] bsr-data",
       CLEAR_STR
       IPV6_STR
       CLEAR_IP_PIM_STR
       VRF_CMD_HELP_STR
       "Reset pim bsr data\n")
{
	struct vrf *v;

	v = vrf_lookup_by_name(vrf ? vrf : VRF_DEFAULT_NAME);
	if (!v)
		return CMD_WARNING;

	pim_bsm_clear(v->info);

	return CMD_SUCCESS;
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

DEFPY (debug_mroute6,
       debug_mroute6_cmd,
       "[no] debug mroute6",
       NO_STR
       DEBUG_STR
       DEBUG_MROUTE6_STR)
{
	if (!no)
		PIM_DO_DEBUG_MROUTE;
	else
		PIM_DONT_DEBUG_MROUTE;

	return CMD_SUCCESS;
}

DEFPY (debug_mroute6_detail,
       debug_mroute6_detail_cmd,
       "[no] debug mroute6 detail",
       NO_STR
       DEBUG_STR
       DEBUG_MROUTE6_STR
       "detailed\n")
{
	if (!no)
		PIM_DO_DEBUG_MROUTE_DETAIL;
	else
		PIM_DONT_DEBUG_MROUTE_DETAIL;

	return CMD_SUCCESS;
}

DEFUN_NOSH (show_debugging_pimv6,
	    show_debugging_pimv6_cmd,
	    "show debugging [pimv6]",
	    SHOW_STR
	    DEBUG_STR
	    "PIMv6 Information\n")
{
	vty_out(vty, "PIMv6 debugging status\n");

	pim_debug_config_write(vty);

	cmd_show_lib_debugs(vty);

	return CMD_SUCCESS;
}

DEFPY (debug_mld,
       debug_mld_cmd,
       "[no] debug mld",
       NO_STR
       DEBUG_STR
       DEBUG_MLD_STR)
{
	if (!no) {
		PIM_DO_DEBUG_GM_EVENTS;
		PIM_DO_DEBUG_GM_PACKETS;
		PIM_DO_DEBUG_GM_TRACE;
	} else {
		PIM_DONT_DEBUG_GM_EVENTS;
		PIM_DONT_DEBUG_GM_PACKETS;
		PIM_DONT_DEBUG_GM_TRACE;
	}

	return CMD_SUCCESS;
}

DEFPY (debug_mld_events,
       debug_mld_events_cmd,
       "[no] debug mld events",
       NO_STR
       DEBUG_STR
       DEBUG_MLD_STR
       DEBUG_MLD_EVENTS_STR)
{
	if (!no)
		PIM_DO_DEBUG_GM_EVENTS;
	else
		PIM_DONT_DEBUG_GM_EVENTS;

	return CMD_SUCCESS;
}

DEFPY (debug_mld_packets,
       debug_mld_packets_cmd,
       "[no] debug mld packets",
       NO_STR
       DEBUG_STR
       DEBUG_MLD_STR
       DEBUG_MLD_PACKETS_STR)
{
	if (!no)
		PIM_DO_DEBUG_GM_PACKETS;
	else
		PIM_DONT_DEBUG_GM_PACKETS;

	return CMD_SUCCESS;
}

DEFPY (debug_mld_trace,
       debug_mld_trace_cmd,
       "[no] debug mld trace",
       NO_STR
       DEBUG_STR
       DEBUG_MLD_STR
       DEBUG_MLD_TRACE_STR)
{
	if (!no)
		PIM_DO_DEBUG_GM_TRACE;
	else
		PIM_DONT_DEBUG_GM_TRACE;

	return CMD_SUCCESS;
}

DEFPY (debug_mld_trace_detail,
       debug_mld_trace_detail_cmd,
       "[no] debug mld trace detail",
       NO_STR
       DEBUG_STR
       DEBUG_MLD_STR
       DEBUG_MLD_TRACE_STR
       "detailed\n")
{
	if (!no)
		PIM_DO_DEBUG_GM_TRACE_DETAIL;
	else
		PIM_DONT_DEBUG_GM_TRACE_DETAIL;

	return CMD_SUCCESS;
}

DEFPY (debug_pimv6_bsm,
       debug_pimv6_bsm_cmd,
       "[no] debug pimv6 bsm",
       NO_STR
       DEBUG_STR
       DEBUG_PIMV6_STR
       DEBUG_PIMV6_BSM_STR)
{
	if (!no)
		PIM_DO_DEBUG_BSM;
	else
		PIM_DONT_DEBUG_BSM;

	return CMD_SUCCESS;
}

struct cmd_node pim6_node = {
	.name = "pim6",
	.node = PIM6_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(config-pim6)# ",
	.config_write = pim_router_config_write,
};

static void pim_install_deprecated(void)
{
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
}

void pim_cmd_init(void)
{
	if_cmd_init(pim_interface_config_write);

	install_node(&debug_node);

	pim_install_deprecated();

	install_element(CONFIG_NODE, &router_pim6_cmd);
	install_element(CONFIG_NODE, &no_router_pim6_cmd);

	install_node(&pim6_node);
	install_default(PIM6_NODE);

	install_element(PIM6_NODE, &pim6_joinprune_time_cmd);
	install_element(PIM6_NODE, &no_pim6_joinprune_time_cmd);
	install_element(PIM6_NODE, &pim6_spt_switchover_infinity_cmd);
	install_element(PIM6_NODE, &pim6_spt_switchover_infinity_plist_cmd);
	install_element(PIM6_NODE, &no_pim6_spt_switchover_infinity_cmd);
	install_element(PIM6_NODE, &no_pim6_spt_switchover_infinity_plist_cmd);
	install_element(PIM6_NODE, &pim6_packets_cmd);
	install_element(PIM6_NODE, &no_pim6_packets_cmd);
	install_element(PIM6_NODE, &pim6_keep_alive_cmd);
	install_element(PIM6_NODE, &no_pim6_keep_alive_cmd);
	install_element(PIM6_NODE, &pim6_rp_keep_alive_cmd);
	install_element(PIM6_NODE, &no_pim6_rp_keep_alive_cmd);
	install_element(PIM6_NODE, &pim6_register_suppress_cmd);
	install_element(PIM6_NODE, &no_pim6_register_suppress_cmd);
	install_element(PIM6_NODE, &pim6_rp_cmd);
	install_element(PIM6_NODE, &no_pim6_rp_cmd);
	install_element(PIM6_NODE, &pim6_rp_prefix_list_cmd);
	install_element(PIM6_NODE, &no_pim6_rp_prefix_list_cmd);
	install_element(PIM6_NODE, &pim6_ssmpingd_cmd);
	install_element(PIM6_NODE, &no_pim6_ssmpingd_cmd);
	install_element(PIM6_NODE, &pim6_bsr_candidate_rp_cmd);
	install_element(PIM6_NODE, &pim6_bsr_candidate_rp_group_cmd);
	install_element(PIM6_NODE, &pim6_bsr_candidate_bsr_cmd);

	install_element(CONFIG_NODE, &ipv6_mld_group_watermark_cmd);
	install_element(VRF_NODE, &ipv6_mld_group_watermark_cmd);
	install_element(CONFIG_NODE, &no_ipv6_mld_group_watermark_cmd);
	install_element(VRF_NODE, &no_ipv6_mld_group_watermark_cmd);

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
	install_element(INTERFACE_NODE, &interface_ipv6_pim_boundary_oil_cmd);
	install_element(INTERFACE_NODE, &interface_no_ipv6_pim_boundary_oil_cmd);
	install_element(INTERFACE_NODE, &interface_ipv6_mroute_cmd);
	install_element(INTERFACE_NODE, &interface_no_ipv6_mroute_cmd);
	/* Install BSM command */
	install_element(INTERFACE_NODE, &ipv6_pim_bsm_cmd);
	install_element(INTERFACE_NODE, &no_ipv6_pim_bsm_cmd);
	install_element(INTERFACE_NODE, &ipv6_pim_ucast_bsm_cmd);
	install_element(INTERFACE_NODE, &no_ipv6_pim_ucast_bsm_cmd);

	install_element(INTERFACE_NODE, &interface_ipv6_mld_cmd);
	install_element(INTERFACE_NODE, &interface_no_ipv6_mld_cmd);
	install_element(INTERFACE_NODE, &interface_ipv6_mld_join_cmd);
	install_element(INTERFACE_NODE, &interface_ipv6_mld_join_group_cmd);
	install_element(INTERFACE_NODE, &interface_ipv6_mld_static_group_cmd);
	install_element(INTERFACE_NODE, &interface_ipv6_mld_version_cmd);
	install_element(INTERFACE_NODE, &interface_no_ipv6_mld_version_cmd);
	install_element(INTERFACE_NODE, &interface_ipv6_mld_query_interval_cmd);
	install_element(INTERFACE_NODE,
			&interface_no_ipv6_mld_query_interval_cmd);
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
	install_element(VIEW_NODE, &show_ipv6_pim_bsr_cand_bsr_cmd);
	install_element(VIEW_NODE, &show_ipv6_pim_bsr_cand_rp_cmd);
	install_element(VIEW_NODE, &show_ipv6_pim_bsr_rpdb_cmd);
	install_element(VIEW_NODE, &show_ipv6_pim_bsr_groups_cmd);
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
	install_element(VIEW_NODE, &show_ipv6_pim_interface_traffic_cmd);
	install_element(VIEW_NODE, &show_ipv6_pim_bsr_cmd);
	install_element(VIEW_NODE, &show_ipv6_pim_bsm_db_cmd);
	install_element(VIEW_NODE, &show_ipv6_pim_bsrp_cmd);
	install_element(ENABLE_NODE, &clear_ipv6_pim_statistics_cmd);
	install_element(ENABLE_NODE, &clear_ipv6_mroute_cmd);
	install_element(ENABLE_NODE, &clear_ipv6_pim_oil_cmd);
	install_element(ENABLE_NODE, &clear_ipv6_mroute_count_cmd);
	install_element(ENABLE_NODE, &clear_ipv6_pim_bsr_db_cmd);
	install_element(ENABLE_NODE, &clear_ipv6_pim_interfaces_cmd);
	install_element(ENABLE_NODE, &clear_ipv6_pim_interface_traffic_cmd);

	install_element(ENABLE_NODE, &show_debugging_pimv6_cmd);

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
	install_element(ENABLE_NODE, &debug_mroute6_cmd);
	install_element(ENABLE_NODE, &debug_mroute6_detail_cmd);
	install_element(ENABLE_NODE, &debug_mld_cmd);
	install_element(ENABLE_NODE, &debug_mld_events_cmd);
	install_element(ENABLE_NODE, &debug_mld_packets_cmd);
	install_element(ENABLE_NODE, &debug_mld_trace_cmd);
	install_element(ENABLE_NODE, &debug_mld_trace_detail_cmd);
	install_element(ENABLE_NODE, &debug_pimv6_bsm_cmd);

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
	install_element(CONFIG_NODE, &debug_mroute6_cmd);
	install_element(CONFIG_NODE, &debug_mroute6_detail_cmd);
	install_element(CONFIG_NODE, &debug_mld_cmd);
	install_element(CONFIG_NODE, &debug_mld_events_cmd);
	install_element(CONFIG_NODE, &debug_mld_packets_cmd);
	install_element(CONFIG_NODE, &debug_mld_trace_cmd);
	install_element(CONFIG_NODE, &debug_mld_trace_detail_cmd);
	install_element(CONFIG_NODE, &debug_pimv6_bsm_cmd);
}
