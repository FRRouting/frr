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
#include "lib/srcdest_table.h"

#include "pimd.h"
#include "pim_vty.h"
#include "lib/northbound_cli.h"
#include "pim_errors.h"
#include "pim_nb.h"
#include "pim_cmd_common.h"

/**
 * Get current node VRF name.
 *
 * NOTE:
 * In case of failure it will print error message to user.
 *
 * \returns name or NULL if failed to get VRF.
 */
const char *pim_cli_get_vrf_name(struct vty *vty)
{
	const struct lyd_node *vrf_node;

	/* Not inside any VRF context. */
	if (vty->xpath_index == 0)
		return VRF_DEFAULT_NAME;

	vrf_node = yang_dnode_get(vty->candidate_config->dnode, VTY_CURR_XPATH);
	if (vrf_node == NULL) {
		vty_out(vty, "%% Failed to get vrf dnode in configuration\n");
		return NULL;
	}

	return yang_dnode_get_string(vrf_node, "./name");
}

int pim_process_join_prune_cmd(struct vty *vty, const char *jpi_str)
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), FRR_PIM_ROUTER_XPATH,
		 FRR_PIM_AF_XPATH_VAL);
	strlcat(xpath, "/join-prune-interval", sizeof(xpath));

	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, jpi_str);

	return nb_cli_apply_changes(vty, NULL);
}

int pim_process_no_join_prune_cmd(struct vty *vty)
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), FRR_PIM_ROUTER_XPATH,
		 FRR_PIM_AF_XPATH_VAL);
	strlcat(xpath, "/join-prune-interval", sizeof(xpath));

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

int pim_process_spt_switchover_infinity_cmd(struct vty *vty)
{
	const char *vrfname;
	char spt_plist_xpath[XPATH_MAXLEN];
	char spt_action_xpath[XPATH_MAXLEN];

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname == NULL)
		return CMD_WARNING_CONFIG_FAILED;

	snprintf(spt_plist_xpath, sizeof(spt_plist_xpath),
		 FRR_PIM_VRF_XPATH, "frr-pim:pimd", "pim", vrfname,
		 FRR_PIM_AF_XPATH_VAL);
	strlcat(spt_plist_xpath, "/spt-switchover/spt-infinity-prefix-list",
		sizeof(spt_plist_xpath));

	snprintf(spt_action_xpath, sizeof(spt_action_xpath),
		 FRR_PIM_VRF_XPATH, "frr-pim:pimd", "pim", vrfname,
		 FRR_PIM_AF_XPATH_VAL);
	strlcat(spt_action_xpath, "/spt-switchover/spt-action",
		sizeof(spt_action_xpath));

	if (yang_dnode_exists(vty->candidate_config->dnode, spt_plist_xpath))
		nb_cli_enqueue_change(vty, spt_plist_xpath, NB_OP_DESTROY,
				      NULL);
	nb_cli_enqueue_change(vty, spt_action_xpath, NB_OP_MODIFY,
			      "PIM_SPT_INFINITY");

	return nb_cli_apply_changes(vty, NULL);
}

int pim_process_spt_switchover_prefixlist_cmd(struct vty *vty,
					      const char *plist)
{
	const char *vrfname;
	char spt_plist_xpath[XPATH_MAXLEN];
	char spt_action_xpath[XPATH_MAXLEN];

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname == NULL)
		return CMD_WARNING_CONFIG_FAILED;

	snprintf(spt_plist_xpath, sizeof(spt_plist_xpath),
		 FRR_PIM_VRF_XPATH, "frr-pim:pimd", "pim", vrfname,
		 FRR_PIM_AF_XPATH_VAL);
	strlcat(spt_plist_xpath, "/spt-switchover/spt-infinity-prefix-list",
		sizeof(spt_plist_xpath));

	snprintf(spt_action_xpath, sizeof(spt_action_xpath),
		 FRR_PIM_VRF_XPATH, "frr-pim:pimd", "pim", vrfname,
		 FRR_PIM_AF_XPATH_VAL);
	strlcat(spt_action_xpath, "/spt-switchover/spt-action",
		sizeof(spt_action_xpath));

	nb_cli_enqueue_change(vty, spt_action_xpath, NB_OP_MODIFY,
			      "PIM_SPT_INFINITY");
	nb_cli_enqueue_change(vty, spt_plist_xpath, NB_OP_MODIFY,
			      plist);

	return nb_cli_apply_changes(vty, NULL);
}

int pim_process_no_spt_switchover_cmd(struct vty *vty)
{
	const char *vrfname;
	char spt_plist_xpath[XPATH_MAXLEN];
	char spt_action_xpath[XPATH_MAXLEN];

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname == NULL)
		return CMD_WARNING_CONFIG_FAILED;

	snprintf(spt_plist_xpath, sizeof(spt_plist_xpath),
		 FRR_PIM_VRF_XPATH, "frr-pim:pimd", "pim", vrfname,
		 FRR_PIM_AF_XPATH_VAL);
	strlcat(spt_plist_xpath, "/spt-switchover/spt-infinity-prefix-list",
		sizeof(spt_plist_xpath));

	snprintf(spt_action_xpath, sizeof(spt_action_xpath),
		 FRR_PIM_VRF_XPATH, "frr-pim:pimd", "pim", vrfname,
		 FRR_PIM_AF_XPATH_VAL);
	strlcat(spt_action_xpath, "/spt-switchover/spt-action",
		sizeof(spt_action_xpath));

	nb_cli_enqueue_change(vty, spt_plist_xpath, NB_OP_DESTROY, NULL);
	nb_cli_enqueue_change(vty, spt_action_xpath, NB_OP_MODIFY,
			      "PIM_SPT_IMMEDIATE");

	return nb_cli_apply_changes(vty, NULL);
}

int pim_process_pim_packet_cmd(struct vty *vty, const char *packet)
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), FRR_PIM_ROUTER_XPATH,
		 FRR_PIM_AF_XPATH_VAL);
	strlcat(xpath, "/packets", sizeof(xpath));

	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, packet);

	return nb_cli_apply_changes(vty, NULL);
}

int pim_process_no_pim_packet_cmd(struct vty *vty)
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), FRR_PIM_ROUTER_XPATH,
		 FRR_PIM_AF_XPATH_VAL);
	strlcat(xpath, "/packets", sizeof(xpath));

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

int pim_process_keepalivetimer_cmd(struct vty *vty, const char *kat)
{
	const char *vrfname;
	char ka_timer_xpath[XPATH_MAXLEN];

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname == NULL)
		return CMD_WARNING_CONFIG_FAILED;

	snprintf(ka_timer_xpath, sizeof(ka_timer_xpath), FRR_PIM_VRF_XPATH,
		 "frr-pim:pimd", "pim", vrfname, FRR_PIM_AF_XPATH_VAL);
	strlcat(ka_timer_xpath, "/keep-alive-timer", sizeof(ka_timer_xpath));

	nb_cli_enqueue_change(vty, ka_timer_xpath, NB_OP_MODIFY,
			      kat);

	return nb_cli_apply_changes(vty, NULL);
}

int pim_process_no_keepalivetimer_cmd(struct vty *vty)
{
	const char *vrfname;
	char ka_timer_xpath[XPATH_MAXLEN];

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname == NULL)
		return CMD_WARNING_CONFIG_FAILED;

	snprintf(ka_timer_xpath, sizeof(ka_timer_xpath), FRR_PIM_VRF_XPATH,
		 "frr-pim:pimd", "pim", vrfname, FRR_PIM_AF_XPATH_VAL);
	strlcat(ka_timer_xpath, "/keep-alive-timer", sizeof(ka_timer_xpath));

	nb_cli_enqueue_change(vty, ka_timer_xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

int pim_process_rp_kat_cmd(struct vty *vty, const char *rpkat)
{
	const char *vrfname;
	char rp_ka_timer_xpath[XPATH_MAXLEN];

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname == NULL)
		return CMD_WARNING_CONFIG_FAILED;

	snprintf(rp_ka_timer_xpath, sizeof(rp_ka_timer_xpath),
		 FRR_PIM_VRF_XPATH, "frr-pim:pimd", "pim", vrfname,
		 FRR_PIM_AF_XPATH_VAL);
	strlcat(rp_ka_timer_xpath, "/rp-keep-alive-timer",
		sizeof(rp_ka_timer_xpath));

	nb_cli_enqueue_change(vty, rp_ka_timer_xpath, NB_OP_MODIFY,
			      rpkat);

	return nb_cli_apply_changes(vty, NULL);
}

int pim_process_no_rp_kat_cmd(struct vty *vty)
{
	const char *vrfname;
	char rp_ka_timer[6];
	char rp_ka_timer_xpath[XPATH_MAXLEN];
	uint v;
	char rs_timer_xpath[XPATH_MAXLEN];

	snprintf(rs_timer_xpath, sizeof(rs_timer_xpath),
		 FRR_PIM_ROUTER_XPATH, FRR_PIM_AF_XPATH_VAL);
	strlcat(rs_timer_xpath, "/register-suppress-time",
		sizeof(rs_timer_xpath));

	/* RFC4601 */
	v = yang_dnode_get_uint16(vty->candidate_config->dnode,
				  rs_timer_xpath);
	v = 3 * v + PIM_REGISTER_PROBE_TIME_DEFAULT;
	if (v > UINT16_MAX)
		v = UINT16_MAX;
	snprintf(rp_ka_timer, sizeof(rp_ka_timer), "%u", v);

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname == NULL)
		return CMD_WARNING_CONFIG_FAILED;

	snprintf(rp_ka_timer_xpath, sizeof(rp_ka_timer_xpath),
		 FRR_PIM_VRF_XPATH, "frr-pim:pimd", "pim", vrfname,
		 FRR_PIM_AF_XPATH_VAL);
	strlcat(rp_ka_timer_xpath, "/rp-keep-alive-timer",
		sizeof(rp_ka_timer_xpath));

	nb_cli_enqueue_change(vty, rp_ka_timer_xpath, NB_OP_MODIFY,
			      rp_ka_timer);

	return nb_cli_apply_changes(vty, NULL);
}

int pim_process_register_suppress_cmd(struct vty *vty, const char *rst)
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), FRR_PIM_ROUTER_XPATH,
		 FRR_PIM_AF_XPATH_VAL);
	strlcat(xpath, "/register-suppress-time", sizeof(xpath));

	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, rst);

	return nb_cli_apply_changes(vty, NULL);
}

int pim_process_no_register_suppress_cmd(struct vty *vty)
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), FRR_PIM_ROUTER_XPATH,
		 FRR_PIM_AF_XPATH_VAL);
	strlcat(xpath, "/register-suppress-time", sizeof(xpath));

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

int pim_process_ip_pim_cmd(struct vty *vty)
{
	nb_cli_enqueue_change(vty, "./pim-enable", NB_OP_MODIFY, "true");

	return nb_cli_apply_changes(vty, FRR_PIM_INTERFACE_XPATH,
				    FRR_PIM_AF_XPATH_VAL);
}

int pim_process_no_ip_pim_cmd(struct vty *vty)
{
	const struct lyd_node *mld_enable_dnode;
	char mld_if_xpath[XPATH_MAXLEN];

	int printed =
		snprintf(mld_if_xpath, sizeof(mld_if_xpath),
			 "%s/frr-gmp:gmp/address-family[address-family='%s']",
			 VTY_CURR_XPATH, FRR_PIM_AF_XPATH_VAL);

	if (printed >= (int)(sizeof(mld_if_xpath))) {
		vty_out(vty, "Xpath too long (%d > %u)", printed + 1,
			XPATH_MAXLEN);
		return CMD_WARNING_CONFIG_FAILED;
	}

	mld_enable_dnode = yang_dnode_getf(vty->candidate_config->dnode,
					   FRR_GMP_ENABLE_XPATH, VTY_CURR_XPATH,
					   FRR_PIM_AF_XPATH_VAL);

	if (!mld_enable_dnode) {
		nb_cli_enqueue_change(vty, mld_if_xpath, NB_OP_DESTROY, NULL);
		nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);
	} else {
		if (!yang_dnode_get_bool(mld_enable_dnode, ".")) {
			nb_cli_enqueue_change(vty, mld_if_xpath, NB_OP_DESTROY,
					      NULL);
			nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);
		} else
			nb_cli_enqueue_change(vty, "./pim-enable", NB_OP_MODIFY,
					      "false");
	}

	return nb_cli_apply_changes(vty, FRR_PIM_INTERFACE_XPATH,
				    FRR_PIM_AF_XPATH_VAL);
}

int pim_process_ip_pim_drprio_cmd(struct vty *vty, const char *drpriority_str)
{
	nb_cli_enqueue_change(vty, "./dr-priority", NB_OP_MODIFY,
			      drpriority_str);

	return nb_cli_apply_changes(vty, FRR_PIM_INTERFACE_XPATH,
				    FRR_PIM_AF_XPATH_VAL);
}

int pim_process_no_ip_pim_drprio_cmd(struct vty *vty)
{
	nb_cli_enqueue_change(vty, "./dr-priority", NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, FRR_PIM_INTERFACE_XPATH,
				    FRR_PIM_AF_XPATH_VAL);
}

int pim_process_ip_pim_hello_cmd(struct vty *vty, const char *hello_str,
				 const char *hold_str)
{
	const struct lyd_node *mld_enable_dnode;

	mld_enable_dnode = yang_dnode_getf(vty->candidate_config->dnode,
					   FRR_GMP_ENABLE_XPATH, VTY_CURR_XPATH,
					   FRR_PIM_AF_XPATH_VAL);

	if (!mld_enable_dnode) {
		nb_cli_enqueue_change(vty, "./pim-enable", NB_OP_MODIFY,
				      "true");
	} else {
		if (!yang_dnode_get_bool(mld_enable_dnode, "."))
			nb_cli_enqueue_change(vty, "./pim-enable", NB_OP_MODIFY,
					      "true");
	}

	nb_cli_enqueue_change(vty, "./hello-interval", NB_OP_MODIFY, hello_str);

	if (hold_str)
		nb_cli_enqueue_change(vty, "./hello-holdtime", NB_OP_MODIFY,
				      hold_str);

	return nb_cli_apply_changes(vty, FRR_PIM_INTERFACE_XPATH,
				    FRR_PIM_AF_XPATH_VAL);
}

int pim_process_no_ip_pim_hello_cmd(struct vty *vty)
{
	nb_cli_enqueue_change(vty, "./hello-interval", NB_OP_DESTROY, NULL);
	nb_cli_enqueue_change(vty, "./hello-holdtime", NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, FRR_PIM_INTERFACE_XPATH,
				    FRR_PIM_AF_XPATH_VAL);
}

int pim_process_ip_pim_activeactive_cmd(struct vty *vty, const char *no)
{
	if (no)
		nb_cli_enqueue_change(vty, "./active-active", NB_OP_MODIFY,
				      "false");
	else {
		nb_cli_enqueue_change(vty, "./pim-enable", NB_OP_MODIFY,
				      "true");

		nb_cli_enqueue_change(vty, "./active-active", NB_OP_MODIFY,
				      "true");
	}

	return nb_cli_apply_changes(vty, FRR_PIM_INTERFACE_XPATH,
				    FRR_PIM_AF_XPATH_VAL);
}

int pim_process_ip_pim_boundary_oil_cmd(struct vty *vty, const char *oil)
{
	nb_cli_enqueue_change(vty, "./multicast-boundary-oil", NB_OP_MODIFY,
			      oil);

	return nb_cli_apply_changes(vty, FRR_PIM_INTERFACE_XPATH,
				    FRR_PIM_AF_XPATH_VAL);
}

int pim_process_no_ip_pim_boundary_oil_cmd(struct vty *vty)
{
	nb_cli_enqueue_change(vty, "./multicast-boundary-oil", NB_OP_DESTROY,
			      NULL);

	return nb_cli_apply_changes(vty, FRR_PIM_INTERFACE_XPATH,
				    FRR_PIM_AF_XPATH_VAL);
}

int pim_process_ip_mroute_cmd(struct vty *vty, const char *interface,
			      const char *group_str, const char *source_str)
{
	nb_cli_enqueue_change(vty, "./oif", NB_OP_MODIFY, interface);

	if (!source_str) {
		char buf[SRCDEST2STR_BUFFER];

		inet_ntop(AF_INET6, &in6addr_any, buf, sizeof(buf));
		return nb_cli_apply_changes(vty, FRR_PIM_MROUTE_XPATH,
					    FRR_PIM_AF_XPATH_VAL, buf,
					    group_str);
	}

	return nb_cli_apply_changes(vty, FRR_PIM_MROUTE_XPATH,
				    FRR_PIM_AF_XPATH_VAL, source_str,
				    group_str);
}

int pim_process_no_ip_mroute_cmd(struct vty *vty, const char *interface,
				 const char *group_str, const char *source_str)
{
	nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);

	if (!source_str) {
		char buf[SRCDEST2STR_BUFFER];

		inet_ntop(AF_INET6, &in6addr_any, buf, sizeof(buf));
		return nb_cli_apply_changes(vty, FRR_PIM_MROUTE_XPATH,
					    FRR_PIM_AF_XPATH_VAL, buf,
					    group_str);
	}

	return nb_cli_apply_changes(vty, FRR_PIM_MROUTE_XPATH,
				    FRR_PIM_AF_XPATH_VAL, source_str,
				    group_str);
}
