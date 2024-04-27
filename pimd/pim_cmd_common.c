// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for IPv6 FRR
 * Copyright (C) 2022  Vmware, Inc.
 *		       Mobashshera Rasool <mrasool@vmware.com>
 */

#include <zebra.h>
#include <sys/ioctl.h>

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
#include "lib/linklist.h"
#include "termtable.h"

#include "pimd.h"
#include "pim_instance.h"
#include "pim_vty.h"
#include "lib/northbound_cli.h"
#include "pim_errors.h"
#include "pim_nb.h"
#include "pim_mroute.h"
#include "pim_cmd.h"
#include "pim6_cmd.h"
#include "pim_cmd_common.h"
#include "pim_time.h"
#include "pim_zebra.h"
#include "pim_zlookup.h"
#include "pim_iface.h"
#include "pim_macro.h"
#include "pim_neighbor.h"
#include "pim_nht.h"
#include "pim_sock.h"
#include "pim_ssm.h"
#include "pim_static.h"
#include "pim_addr.h"
#include "pim_static.h"
#include "pim_util.h"
#include "pim6_mld.h"

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

	return yang_dnode_get_string(vrf_node, "name");
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
	/* Check if register suppress time is configured or assigned
	 * the default register suppress time.
	 */
	if (yang_dnode_exists(vty->candidate_config->dnode, rs_timer_xpath))
		v = yang_dnode_get_uint16(vty->candidate_config->dnode, "%s",
					  rs_timer_xpath);
	else
		v = PIM_REGISTER_SUPPRESSION_TIME_DEFAULT;

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

int pim_process_ip_pim_passive_cmd(struct vty *vty, bool enable)
{
	if (enable)
		nb_cli_enqueue_change(vty, "./pim-passive-enable", NB_OP_MODIFY,
				      "true");
	else
		nb_cli_enqueue_change(vty, "./pim-passive-enable", NB_OP_MODIFY,
				      "false");

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

int pim_process_rp_cmd(struct vty *vty, const char *rp_str,
		       const char *group_str)
{
	const char *vrfname;
	char group_xpath[XPATH_MAXLEN];
	char rp_xpath[XPATH_MAXLEN];
	int printed;
	int result = 0;
	struct prefix group;
	pim_addr rp_addr;

	result = str2prefix(group_str, &group);
	if (result) {
		struct prefix temp;

		prefix_copy(&temp, &group);
		apply_mask(&temp);
		if (!prefix_same(&group, &temp)) {
			vty_out(vty, "%% Inconsistent address and mask: %s\n",
				group_str);
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	if (!result) {
		vty_out(vty, "%% Bad group address specified: %s\n", group_str);
		return CMD_WARNING_CONFIG_FAILED;
	}

	result = inet_pton(PIM_AF, rp_str, &rp_addr);
	if (result <= 0) {
		vty_out(vty, "%% Bad RP address specified: %s\n", rp_str);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (pim_addr_is_any(rp_addr) || pim_addr_is_multicast(rp_addr)) {
		vty_out(vty, "%% Bad RP address specified: %s\n", rp_str);
		return CMD_WARNING_CONFIG_FAILED;
	}

#if PIM_IPV == 6
	if (IN6_IS_ADDR_LINKLOCAL(&rp_addr)) {
		vty_out(vty, "%% Bad RP address specified: %s\n", rp_str);
		return CMD_WARNING_CONFIG_FAILED;
	}
#endif

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname == NULL)
		return CMD_WARNING_CONFIG_FAILED;

	snprintf(rp_xpath, sizeof(rp_xpath), FRR_PIM_STATIC_RP_XPATH,
		 "frr-pim:pimd", "pim", vrfname, FRR_PIM_AF_XPATH_VAL, rp_str);
	printed = snprintf(group_xpath, sizeof(group_xpath),
			   "%s/group-list[.='%s']", rp_xpath, group_str);

	if (printed >= (int)(sizeof(group_xpath))) {
		vty_out(vty, "Xpath too long (%d > %u)", printed + 1,
			XPATH_MAXLEN);
		return CMD_WARNING_CONFIG_FAILED;
	}

	nb_cli_enqueue_change(vty, group_xpath, NB_OP_CREATE, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

int pim_process_no_rp_cmd(struct vty *vty, const char *rp_str,
			  const char *group_str)
{
	char group_xpath[XPATH_MAXLEN];
	char rp_xpath[XPATH_MAXLEN];
	int printed;
	const char *vrfname;
	const struct lyd_node *group_dnode;

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname == NULL)
		return CMD_WARNING_CONFIG_FAILED;

	snprintf(rp_xpath, sizeof(rp_xpath), FRR_PIM_STATIC_RP_XPATH,
		 "frr-pim:pimd", "pim", vrfname, FRR_PIM_AF_XPATH_VAL, rp_str);
	printed = snprintf(group_xpath, sizeof(group_xpath),
			   "%s/group-list[.='%s']", rp_xpath, group_str);

	if (printed >= (int)(sizeof(group_xpath))) {
		vty_out(vty, "Xpath too long (%d > %u)", printed + 1,
			XPATH_MAXLEN);
		return CMD_WARNING_CONFIG_FAILED;
	}

	group_dnode = yang_dnode_get(vty->candidate_config->dnode, group_xpath);
	if (!group_dnode) {
		vty_out(vty, "%% Unable to find specified RP\n");
		return NB_OK;
	}

	if (yang_is_last_list_dnode(group_dnode))
		nb_cli_enqueue_change(vty, rp_xpath, NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, group_xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

int pim_process_rp_plist_cmd(struct vty *vty, const char *rp_str,
			     const char *prefix_list)
{
	const char *vrfname;
	char rp_plist_xpath[XPATH_MAXLEN];

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname == NULL)
		return CMD_WARNING_CONFIG_FAILED;

	snprintf(rp_plist_xpath, sizeof(rp_plist_xpath),
		 FRR_PIM_STATIC_RP_XPATH, "frr-pim:pimd", "pim", vrfname,
		 FRR_PIM_AF_XPATH_VAL, rp_str);
	strlcat(rp_plist_xpath, "/prefix-list", sizeof(rp_plist_xpath));

	nb_cli_enqueue_change(vty, rp_plist_xpath, NB_OP_MODIFY, prefix_list);

	return nb_cli_apply_changes(vty, NULL);
}

int pim_process_no_rp_plist_cmd(struct vty *vty, const char *rp_str,
				const char *prefix_list)
{
	char rp_xpath[XPATH_MAXLEN];
	char plist_xpath[XPATH_MAXLEN];
	const char *vrfname;
	const struct lyd_node *plist_dnode;
	const char *plist;

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname == NULL)
		return CMD_WARNING_CONFIG_FAILED;

	snprintf(rp_xpath, sizeof(rp_xpath), FRR_PIM_STATIC_RP_XPATH,
		 "frr-pim:pimd", "pim", vrfname, FRR_PIM_AF_XPATH_VAL, rp_str);

	snprintf(plist_xpath, sizeof(plist_xpath), FRR_PIM_STATIC_RP_XPATH,
		 "frr-pim:pimd", "pim", vrfname, FRR_PIM_AF_XPATH_VAL, rp_str);
	strlcat(plist_xpath, "/prefix-list", sizeof(plist_xpath));

	plist_dnode = yang_dnode_get(vty->candidate_config->dnode, plist_xpath);
	if (!plist_dnode) {
		vty_out(vty, "%% Unable to find specified RP\n");
		return NB_OK;
	}

	plist = yang_dnode_get_string(plist_dnode, "%s", plist_xpath);
	if (strcmp(prefix_list, plist)) {
		vty_out(vty, "%% Unable to find specified RP\n");
		return NB_OK;
	}

	nb_cli_enqueue_change(vty, rp_xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

bool pim_sgaddr_match(pim_sgaddr item, pim_sgaddr match)
{
	return (pim_addr_is_any(match.grp) ||
		!pim_addr_cmp(match.grp, item.grp)) &&
	       (pim_addr_is_any(match.src) ||
		!pim_addr_cmp(match.src, item.src));
}

void json_object_pim_ifp_add(struct json_object *json, struct interface *ifp)
{
	struct pim_interface *pim_ifp;

	pim_ifp = ifp->info;
	json_object_string_add(json, "name", ifp->name);
	json_object_string_add(json, "state", if_is_up(ifp) ? "up" : "down");
	json_object_string_addf(json, "address", "%pPA",
				&pim_ifp->primary_address);
	json_object_int_add(json, "index", ifp->ifindex);

	if (if_is_multicast(ifp))
		json_object_boolean_true_add(json, "flagMulticast");

	if (if_is_broadcast(ifp))
		json_object_boolean_true_add(json, "flagBroadcast");

	if (ifp->flags & IFF_ALLMULTI)
		json_object_boolean_true_add(json, "flagAllMulticast");

	if (ifp->flags & IFF_PROMISC)
		json_object_boolean_true_add(json, "flagPromiscuous");

	if (PIM_IF_IS_DELETED(ifp))
		json_object_boolean_true_add(json, "flagDeleted");

	if (pim_if_lan_delay_enabled(ifp))
		json_object_boolean_true_add(json, "lanDelayEnabled");
}

void pim_print_ifp_flags(struct vty *vty, struct interface *ifp)
{
	vty_out(vty, "Flags\n");
	vty_out(vty, "-----\n");
	vty_out(vty, "All Multicast   : %s\n",
		(ifp->flags & IFF_ALLMULTI) ? "yes" : "no");
	vty_out(vty, "Broadcast       : %s\n",
		if_is_broadcast(ifp) ? "yes" : "no");
	vty_out(vty, "Deleted         : %s\n",
		PIM_IF_IS_DELETED(ifp) ? "yes" : "no");
	vty_out(vty, "Interface Index : %d\n", ifp->ifindex);
	vty_out(vty, "Multicast       : %s\n",
		if_is_multicast(ifp) ? "yes" : "no");
	vty_out(vty, "Promiscuous     : %s\n",
		(ifp->flags & IFF_PROMISC) ? "yes" : "no");
	vty_out(vty, "\n");
	vty_out(vty, "\n");
}

void json_object_pim_upstream_add(json_object *json, struct pim_upstream *up)
{
	json_object_boolean_add(
		json, "drJoinDesired",
		CHECK_FLAG(up->flags, PIM_UPSTREAM_FLAG_MASK_DR_JOIN_DESIRED));
	json_object_boolean_add(
		json, "drJoinDesiredUpdated",
		CHECK_FLAG(up->flags,
			   PIM_UPSTREAM_FLAG_MASK_DR_JOIN_DESIRED_UPDATED));
	json_object_boolean_add(
		json, "firstHopRouter",
		CHECK_FLAG(up->flags, PIM_UPSTREAM_FLAG_MASK_FHR));
	json_object_boolean_add(
		json, "sourceIgmp",
		CHECK_FLAG(up->flags, PIM_UPSTREAM_FLAG_MASK_SRC_IGMP));
	json_object_boolean_add(
		json, "sourcePim",
		CHECK_FLAG(up->flags, PIM_UPSTREAM_FLAG_MASK_SRC_PIM));
	json_object_boolean_add(
		json, "sourceStream",
		CHECK_FLAG(up->flags, PIM_UPSTREAM_FLAG_MASK_SRC_STREAM));
	/* XXX: need to print ths flag in the plain text display as well */
	json_object_boolean_add(
		json, "sourceMsdp",
		CHECK_FLAG(up->flags, PIM_UPSTREAM_FLAG_MASK_SRC_MSDP));
	json_object_boolean_add(
		json, "sendSGRptPrune",
		CHECK_FLAG(up->flags,
			   PIM_UPSTREAM_FLAG_MASK_SEND_SG_RPT_PRUNE));
	json_object_boolean_add(
		json, "lastHopRouter",
		CHECK_FLAG(up->flags, PIM_UPSTREAM_FLAG_MASK_SRC_LHR));
	json_object_boolean_add(
		json, "disableKATExpiry",
		CHECK_FLAG(up->flags,
			   PIM_UPSTREAM_FLAG_MASK_DISABLE_KAT_EXPIRY));
	json_object_boolean_add(
		json, "staticIncomingInterface",
		CHECK_FLAG(up->flags, PIM_UPSTREAM_FLAG_MASK_STATIC_IIF));
	json_object_boolean_add(
		json, "allowIncomingInterfaceinOil",
		CHECK_FLAG(up->flags, PIM_UPSTREAM_FLAG_MASK_ALLOW_IIF_IN_OIL));
	json_object_boolean_add(
		json, "noPimRegistrationData",
		CHECK_FLAG(up->flags, PIM_UPSTREAM_FLAG_MASK_NO_PIMREG_DATA));
	json_object_boolean_add(
		json, "forcePimRegistration",
		CHECK_FLAG(up->flags, PIM_UPSTREAM_FLAG_MASK_FORCE_PIMREG));
	json_object_boolean_add(
		json, "sourceVxlanOrigination",
		CHECK_FLAG(up->flags, PIM_UPSTREAM_FLAG_MASK_SRC_VXLAN_ORIG));
	json_object_boolean_add(
		json, "sourceVxlanTermination",
		CHECK_FLAG(up->flags, PIM_UPSTREAM_FLAG_MASK_SRC_VXLAN_TERM));
	json_object_boolean_add(
		json, "mlagVxlan",
		CHECK_FLAG(up->flags, PIM_UPSTREAM_FLAG_MASK_MLAG_VXLAN));
	json_object_boolean_add(
		json, "mlagNonDesignatedForwarder",
		CHECK_FLAG(up->flags, PIM_UPSTREAM_FLAG_MASK_MLAG_NON_DF));
}

static const char *
pim_upstream_state2brief_str(enum pim_upstream_state join_state,
			     char *state_str, size_t state_str_len)
{
	switch (join_state) {
	case PIM_UPSTREAM_NOTJOINED:
		strlcpy(state_str, "NotJ", state_str_len);
		break;
	case PIM_UPSTREAM_JOINED:
		strlcpy(state_str, "J", state_str_len);
		break;
	default:
		strlcpy(state_str, "Unk", state_str_len);
	}
	return state_str;
}

static const char *pim_reg_state2brief_str(enum pim_reg_state reg_state,
					   char *state_str,
					   size_t state_str_len)
{
	switch (reg_state) {
	case PIM_REG_NOINFO:
		strlcpy(state_str, "RegNI", state_str_len);
		break;
	case PIM_REG_JOIN:
		strlcpy(state_str, "RegJ", state_str_len);
		break;
	case PIM_REG_JOIN_PENDING:
	case PIM_REG_PRUNE:
		strlcpy(state_str, "RegP", state_str_len);
		break;
	}
	return state_str;
}

void pim_show_rpf_refresh_stats(struct vty *vty, struct pim_instance *pim,
				time_t now, json_object *json)
{
	char refresh_uptime[10];

	pim_time_uptime_begin(refresh_uptime, sizeof(refresh_uptime), now,
			      pim->rpf_cache_refresh_last);

	if (json) {
		json_object_int_add(json, "rpfCacheRefreshDelayMsecs",
				    router->rpf_cache_refresh_delay_msec);
		json_object_int_add(
			json, "rpfCacheRefreshTimer",
			pim_time_timer_remain_msec(pim->rpf_cache_refresher));
		json_object_int_add(json, "rpfCacheRefreshRequests",
				    pim->rpf_cache_refresh_requests);
		json_object_int_add(json, "rpfCacheRefreshEvents",
				    pim->rpf_cache_refresh_events);
		json_object_string_add(json, "rpfCacheRefreshLast",
				       refresh_uptime);
		json_object_int_add(json, "nexthopLookups",
				    pim->nexthop_lookups);
		json_object_int_add(json, "nexthopLookupsAvoided",
				    pim->nexthop_lookups_avoided);
	} else {
		vty_out(vty,
			"RPF Cache Refresh Delay:    %ld msecs\n"
			"RPF Cache Refresh Timer:    %ld msecs\n"
			"RPF Cache Refresh Requests: %lld\n"
			"RPF Cache Refresh Events:   %lld\n"
			"RPF Cache Refresh Last:     %s\n"
			"Nexthop Lookups:            %lld\n"
			"Nexthop Lookups Avoided:    %lld\n",
			router->rpf_cache_refresh_delay_msec,
			pim_time_timer_remain_msec(pim->rpf_cache_refresher),
			(long long)pim->rpf_cache_refresh_requests,
			(long long)pim->rpf_cache_refresh_events,
			refresh_uptime, (long long)pim->nexthop_lookups,
			(long long)pim->nexthop_lookups_avoided);
	}
}

void pim_show_rpf(struct pim_instance *pim, struct vty *vty, json_object *json)
{
	struct pim_upstream *up;
	time_t now = pim_time_monotonic_sec();
	struct ttable *tt = NULL;
	char *table = NULL;
	json_object *json_group = NULL;
	json_object *json_row = NULL;

	pim_show_rpf_refresh_stats(vty, pim, now, json);

	if (!json) {
		vty_out(vty, "\n");

		/* Prepare table. */
		tt = ttable_new(&ttable_styles[TTSTYLE_BLANK]);
		ttable_add_row(
			tt,
			"Source|Group|RpfIface|RpfAddress|RibNextHop|Metric|Pref");
		tt->style.cell.rpad = 2;
		tt->style.corner = '+';
		ttable_restyle(tt);
	}

	frr_each (rb_pim_upstream, &pim->upstream_head, up) {
		const char *rpf_ifname;
		struct pim_rpf *rpf = &up->rpf;

		rpf_ifname =
			rpf->source_nexthop.interface ? rpf->source_nexthop
								.interface->name
						      : "<ifname?>";

		if (json) {
			char grp_str[PIM_ADDRSTRLEN];
			char src_str[PIM_ADDRSTRLEN];

			snprintfrr(grp_str, sizeof(grp_str), "%pPAs",
				   &up->sg.grp);
			snprintfrr(src_str, sizeof(src_str), "%pPAs",
				   &up->sg.src);

			json_object_object_get_ex(json, grp_str, &json_group);

			if (!json_group) {
				json_group = json_object_new_object();
				json_object_object_add(json, grp_str,
						       json_group);
			}

			json_row = json_object_new_object();
			json_object_string_add(json_row, "source", src_str);
			json_object_string_add(json_row, "group", grp_str);
			json_object_string_add(json_row, "rpfInterface",
					       rpf_ifname);
			json_object_string_addf(json_row, "rpfAddress", "%pPA",
						&rpf->rpf_addr);
			json_object_string_addf(
				json_row, "ribNexthop", "%pPAs",
				&rpf->source_nexthop.mrib_nexthop_addr);
			json_object_int_add(
				json_row, "routeMetric",
				rpf->source_nexthop.mrib_route_metric);
			json_object_int_add(
				json_row, "routePreference",
				rpf->source_nexthop.mrib_metric_preference);
			json_object_object_add(json_group, src_str, json_row);

		} else {
			ttable_add_row(
				tt, "%pPAs|%pPAs|%s|%pPA|%pPAs|%d|%d",
				&up->sg.src, &up->sg.grp, rpf_ifname,
				&rpf->rpf_addr,
				&rpf->source_nexthop.mrib_nexthop_addr,
				rpf->source_nexthop.mrib_route_metric,
				rpf->source_nexthop.mrib_metric_preference);
		}
	}
	/* Dump the generated table. */
	if (!json) {
		table = ttable_dump(tt, "\n");
		vty_out(vty, "%s\n", table);
		XFREE(MTYPE_TMP, table);
		ttable_del(tt);
	}
}

void pim_show_neighbors_secondary(struct pim_instance *pim, struct vty *vty)
{
	struct interface *ifp;
	struct ttable *tt = NULL;
	char *table = NULL;

	/* Prepare table. */
	tt = ttable_new(&ttable_styles[TTSTYLE_BLANK]);
	ttable_add_row(tt, "Interface|Address|Neighbor|Secondary");
	tt->style.cell.rpad = 2;
	tt->style.corner = '+';
	ttable_restyle(tt);

	FOR_ALL_INTERFACES (pim->vrf, ifp) {
		struct pim_interface *pim_ifp;
		pim_addr ifaddr;
		struct listnode *neighnode;
		struct pim_neighbor *neigh;

		pim_ifp = ifp->info;

		if (!pim_ifp)
			continue;

		if (pim_ifp->pim_sock_fd < 0)
			continue;

		ifaddr = pim_ifp->primary_address;

		for (ALL_LIST_ELEMENTS_RO(pim_ifp->pim_neighbor_list, neighnode,
					  neigh)) {
			struct listnode *prefix_node;
			struct prefix *p;

			if (!neigh->prefix_list)
				continue;

			for (ALL_LIST_ELEMENTS_RO(neigh->prefix_list,
						  prefix_node, p))
				ttable_add_row(tt, "%s|%pPAs|%pPAs|%pFX",
					       ifp->name, &ifaddr,
					       &neigh->source_addr, p);
		}
	}
	/* Dump the generated table. */
	table = ttable_dump(tt, "\n");
	vty_out(vty, "%s\n", table);
	XFREE(MTYPE_TMP, table);
	ttable_del(tt);
}

void pim_show_state(struct pim_instance *pim, struct vty *vty,
		    const char *src_or_group, const char *group,
		    json_object *json)
{
	struct channel_oil *c_oil;
#if PIM_IPV != 4
	struct ttable *tt = NULL;
	char *table = NULL;
#endif
	char flag[50];
	json_object *json_group = NULL;
	json_object *json_ifp_in = NULL;
	json_object *json_ifp_out = NULL;
	json_object *json_source = NULL;
	time_t now;
	int first_oif;

	now = pim_time_monotonic_sec();

	if (!json) {
		vty_out(vty,
			"Codes: J -> Pim Join, I -> " GM " Report, S -> Source, * -> Inherited from (*,G), V -> VxLAN, M -> Muted\n");
#if PIM_IPV == 4
		vty_out(vty,
			"Active Source           Group            RPT  IIF               OIL\n");
#else
		/* Prepare table. */
		tt = ttable_new(&ttable_styles[TTSTYLE_BLANK]);
		ttable_add_row(tt, "Active|Source|Group|RPT|IIF|OIL");
		tt->style.cell.rpad = 2;
		tt->style.corner = '+';
		ttable_restyle(tt);
#endif
	}

	frr_each (rb_pim_oil, &pim->channel_oil_head, c_oil) {
		char src_str[PIM_ADDRSTRLEN];
		char grp_str[PIM_ADDRSTRLEN];
		char in_ifname[IFNAMSIZ + 1];
		char out_ifname[IFNAMSIZ + 1];
		int oif_vif_index;
		struct interface *ifp_in;
		bool isRpt;

		first_oif = 1;

		if ((c_oil->up &&
		     PIM_UPSTREAM_FLAG_TEST_USE_RPT(c_oil->up->flags)) ||
		    pim_addr_is_any(*oil_origin(c_oil)))
			isRpt = true;
		else
			isRpt = false;

		snprintfrr(grp_str, sizeof(grp_str), "%pPAs",
			   oil_mcastgrp(c_oil));
		snprintfrr(src_str, sizeof(src_str), "%pPAs",
			   oil_origin(c_oil));
		ifp_in = pim_if_find_by_vif_index(pim, *oil_incoming_vif(c_oil));

		if (ifp_in)
			strlcpy(in_ifname, ifp_in->name, sizeof(in_ifname));
		else
			strlcpy(in_ifname, "<iif?>", sizeof(in_ifname));

		if (src_or_group) {
			if (strcmp(src_or_group, src_str) &&
			    strcmp(src_or_group, grp_str))
				continue;

			if (group && strcmp(group, grp_str))
				continue;
		}

		if (json) {

			/* Find the group, create it if it doesn't exist */
			json_object_object_get_ex(json, grp_str, &json_group);

			if (!json_group) {
				json_group = json_object_new_object();
				json_object_object_add(json, grp_str,
						       json_group);
			}

			/* Find the source nested under the group, create it if
			 * it doesn't exist
			 */
			json_object_object_get_ex(json_group, src_str,
						  &json_source);

			if (!json_source) {
				json_source = json_object_new_object();
				json_object_object_add(json_group, src_str,
						       json_source);
			}

			/* Find the inbound interface nested under the source,
			 * create it if it doesn't exist
			 */
			json_object_object_get_ex(json_source, in_ifname,
						  &json_ifp_in);

			if (!json_ifp_in) {
				json_ifp_in = json_object_new_object();
				json_object_object_add(json_source, in_ifname,
						       json_ifp_in);
				json_object_int_add(json_source, "installed",
						    c_oil->installed);
				json_object_boolean_add(json_source, "isRpt",
							isRpt);
				json_object_int_add(json_source, "refCount",
						    c_oil->oil_ref_count);
				json_object_int_add(json_source, "oilListSize",
						    c_oil->oil_size);
				json_object_int_add(
					json_source, "oilRescan",
					c_oil->oil_inherited_rescan);
				json_object_int_add(json_source, "lastUsed",
						    c_oil->cc.lastused);
				json_object_int_add(json_source, "packetCount",
						    c_oil->cc.pktcnt);
				json_object_int_add(json_source, "byteCount",
						    c_oil->cc.bytecnt);
				json_object_int_add(json_source,
						    "wrongInterface",
						    c_oil->cc.wrong_if);
			}
		} else
#if PIM_IPV == 4
			vty_out(vty, "%-6d %-15pPAs  %-15pPAs  %-3s  %-16s  ",
				c_oil->installed, oil_origin(c_oil),
				oil_mcastgrp(c_oil), isRpt ? "y" : "n",
				in_ifname);
#else
			/* Add a new row for c_oil with no OIF */
			ttable_add_row(tt, "%d|%pPAs|%pPAs|%s|%s|%c",
				       c_oil->installed, oil_origin(c_oil),
				       oil_mcastgrp(c_oil), isRpt ? "y" : "n",
				       in_ifname, ' ');
#endif

		for (oif_vif_index = 0; oif_vif_index < MAXVIFS;
		     ++oif_vif_index) {
			struct interface *ifp_out;
			char oif_uptime[10];
			int ttl;

			ttl = oil_if_has(c_oil, oif_vif_index);
			if (ttl < 1)
				continue;

			ifp_out = pim_if_find_by_vif_index(pim, oif_vif_index);
			pim_time_uptime(
				oif_uptime, sizeof(oif_uptime),
				now - c_oil->oif_creation[oif_vif_index]);

			if (ifp_out)
				strlcpy(out_ifname, ifp_out->name,
					sizeof(out_ifname));
			else
				strlcpy(out_ifname, "<oif?>",
					sizeof(out_ifname));

			if (json) {
				json_ifp_out = json_object_new_object();
				json_object_string_add(json_ifp_out, "source",
						       src_str);
				json_object_string_add(json_ifp_out, "group",
						       grp_str);
				json_object_string_add(json_ifp_out,
						       "inboundInterface",
						       in_ifname);
				json_object_string_add(json_ifp_out,
						       "outboundInterface",
						       out_ifname);
				json_object_int_add(json_ifp_out, "installed",
						    c_oil->installed);

				json_object_object_add(json_ifp_in, out_ifname,
						       json_ifp_out);
			} else {
				flag[0] = '\0';
				snprintf(flag, sizeof(flag), "(%c%c%c%c%c)",
					 (c_oil->oif_flags[oif_vif_index] &
					  PIM_OIF_FLAG_PROTO_GM)
						 ? 'I'
						 : ' ',
					 (c_oil->oif_flags[oif_vif_index] &
					  PIM_OIF_FLAG_PROTO_PIM)
						 ? 'J'
						 : ' ',
					 (c_oil->oif_flags[oif_vif_index] &
					  PIM_OIF_FLAG_PROTO_VXLAN)
						 ? 'V'
						 : ' ',
					 (c_oil->oif_flags[oif_vif_index] &
					  PIM_OIF_FLAG_PROTO_STAR)
						 ? '*'
						 : ' ',
					 (c_oil->oif_flags[oif_vif_index] &
					  PIM_OIF_FLAG_MUTE)
						 ? 'M'
						 : ' ');

				if (first_oif) {
					first_oif = 0;
#if PIM_IPV == 4
					vty_out(vty, "%s%s", out_ifname, flag);
#else
					/* OIF found.
					 * Delete the existing row for c_oil,
					 * with no OIF.
					 * Add a new row for c_oil with OIF and
					 * flag.
					 */
					ttable_del_row(tt, tt->nrows - 1);
					ttable_add_row(
						tt, "%d|%pPAs|%pPAs|%s|%s|%s%s",
						c_oil->installed,
						oil_origin(c_oil),
						oil_mcastgrp(c_oil),
						isRpt ? "y" : "n", in_ifname,
						out_ifname, flag);
#endif
				} else {
#if PIM_IPV == 4
					vty_out(vty, ", %s%s", out_ifname,
						flag);
#else
					ttable_add_row(tt,
						       "%c|%c|%c|%c|%c|%s%s",
						       ' ', ' ', ' ', ' ', ' ',
						       out_ifname, flag);
#endif
				}
			}
		}
#if PIM_IPV == 4
		if (!json)
			vty_out(vty, "\n");
#endif
	}

	/* Dump the generated table. */
	if (!json) {
#if PIM_IPV == 4
		vty_out(vty, "\n");
#else
		table = ttable_dump(tt, "\n");
		vty_out(vty, "%s\n", table);
		XFREE(MTYPE_TMP, table);
		ttable_del(tt);
#endif
	}
}

/* pim statistics - just adding only bsm related now.
 * We can continue to add all pim related stats here.
 */
void pim_show_statistics(struct pim_instance *pim, struct vty *vty,
			 const char *ifname, bool uj)
{
	json_object *json = NULL;
	struct interface *ifp;

	if (uj) {
		json = json_object_new_object();
		json_object_int_add(json, "bsmRx", pim->bsm_rcvd);
		json_object_int_add(json, "bsmTx", pim->bsm_sent);
		json_object_int_add(json, "bsmDropped", pim->bsm_dropped);
	} else {
		vty_out(vty, "BSM Statistics :\n");
		vty_out(vty, "----------------\n");
		vty_out(vty, "Number of Received BSMs : %" PRIu64 "\n",
			pim->bsm_rcvd);
		vty_out(vty, "Number of Forwared BSMs : %" PRIu64 "\n",
			pim->bsm_sent);
		vty_out(vty, "Number of Dropped BSMs  : %" PRIu64 "\n",
			pim->bsm_dropped);
	}

	vty_out(vty, "\n");

	/* scan interfaces */
	FOR_ALL_INTERFACES (pim->vrf, ifp) {
		struct pim_interface *pim_ifp = ifp->info;

		if (ifname && strcmp(ifname, ifp->name))
			continue;

		if (!pim_ifp)
			continue;

		if (!uj) {
			vty_out(vty, "Interface : %s\n", ifp->name);
			vty_out(vty, "-------------------\n");
			vty_out(vty,
				"Number of BSMs dropped due to config miss : %u\n",
				pim_ifp->pim_ifstat_bsm_cfg_miss);
			vty_out(vty, "Number of unicast BSMs dropped : %u\n",
				pim_ifp->pim_ifstat_ucast_bsm_cfg_miss);
			vty_out(vty,
				"Number of BSMs dropped due to invalid scope zone : %u\n",
				pim_ifp->pim_ifstat_bsm_invalid_sz);
		} else {

			json_object *json_row = NULL;

			json_row = json_object_new_object();

			json_object_string_add(json_row, "If Name", ifp->name);
			json_object_int_add(json_row, "bsmDroppedConfig",
					    pim_ifp->pim_ifstat_bsm_cfg_miss);
			json_object_int_add(
				json_row, "bsmDroppedUnicast",
				pim_ifp->pim_ifstat_ucast_bsm_cfg_miss);
			json_object_int_add(json_row,
					    "bsmDroppedInvalidScopeZone",
					    pim_ifp->pim_ifstat_bsm_invalid_sz);
			json_object_object_add(json, ifp->name, json_row);
		}
		vty_out(vty, "\n");
	}

	if (uj)
		vty_json(vty, json);
}

void pim_show_upstream(struct pim_instance *pim, struct vty *vty,
		       pim_sgaddr *sg, json_object *json)
{
	struct pim_upstream *up;
	struct ttable *tt = NULL;
	char *table = NULL;
	time_t now;
	json_object *json_group = NULL;
	json_object *json_row = NULL;

	now = pim_time_monotonic_sec();

	if (!json) {
		/* Prepare table. */
		tt = ttable_new(&ttable_styles[TTSTYLE_BLANK]);
		ttable_add_row(
			tt,
			"Iif|Source|Group|State|Uptime|JoinTimer|RSTimer|KATimer|RefCnt");
		tt->style.cell.rpad = 2;
		tt->style.corner = '+';
		ttable_restyle(tt);
	}

	frr_each (rb_pim_upstream, &pim->upstream_head, up) {
		char uptime[10];
		char join_timer[10];
		char rs_timer[10];
		char ka_timer[10];
		char msdp_reg_timer[10];
		char state_str[PIM_REG_STATE_STR_LEN];

		if (!pim_sgaddr_match(up->sg, *sg))
			continue;

		pim_time_uptime(uptime, sizeof(uptime),
				now - up->state_transition);
		pim_time_timer_to_hhmmss(join_timer, sizeof(join_timer),
					 up->t_join_timer);

		/*
		 * If the upstream is not dummy and it has a J/P timer for the
		 * neighbor display that
		 */
		if (!up->t_join_timer && up->rpf.source_nexthop.interface) {
			struct pim_neighbor *nbr;

			nbr = pim_neighbor_find(
				up->rpf.source_nexthop.interface,
				up->rpf.rpf_addr, false);
			if (nbr)
				pim_time_timer_to_hhmmss(join_timer,
							 sizeof(join_timer),
							 nbr->jp_timer);
		}

		pim_time_timer_to_hhmmss(rs_timer, sizeof(rs_timer),
					 up->t_rs_timer);
		pim_time_timer_to_hhmmss(ka_timer, sizeof(ka_timer),
					 up->t_ka_timer);
		pim_time_timer_to_hhmmss(msdp_reg_timer, sizeof(msdp_reg_timer),
					 up->t_msdp_reg_timer);

		pim_upstream_state2brief_str(up->join_state, state_str,
					     sizeof(state_str));
		if (up->reg_state != PIM_REG_NOINFO) {
			char tmp_str[PIM_REG_STATE_STR_LEN];
			char tmp[sizeof(state_str) + 1];

			snprintf(tmp, sizeof(tmp), ",%s",
				 pim_reg_state2brief_str(up->reg_state, tmp_str,
							 sizeof(tmp_str)));
			strlcat(state_str, tmp, sizeof(state_str));
		}

		if (json) {
			char grp_str[PIM_ADDRSTRLEN];
			char src_str[PIM_ADDRSTRLEN];

			snprintfrr(grp_str, sizeof(grp_str), "%pPAs",
				   &up->sg.grp);
			snprintfrr(src_str, sizeof(src_str), "%pPAs",
				   &up->sg.src);

			json_object_object_get_ex(json, grp_str, &json_group);

			if (!json_group) {
				json_group = json_object_new_object();
				json_object_object_add(json, grp_str,
						       json_group);
			}

			json_row = json_object_new_object();
			json_object_pim_upstream_add(json_row, up);
			json_object_string_add(
				json_row, "inboundInterface",
				up->rpf.source_nexthop.interface
				? up->rpf.source_nexthop.interface->name
				: "Unknown");

			/*
			 * The RPF address we use is slightly different
			 * based upon what we are looking up.
			 * If we have a S, list that unless
			 * we are the FHR, else we just put
			 * the RP as the rpfAddress
			 */
			if (up->flags & PIM_UPSTREAM_FLAG_MASK_FHR ||
			    pim_addr_is_any(up->sg.src)) {
				struct pim_rpf *rpg;

				rpg = RP(pim, up->sg.grp);
				json_object_string_addf(json_row, "rpfAddress",
							"%pPA", &rpg->rpf_addr);
			} else {
				json_object_string_add(json_row, "rpfAddress",
						       src_str);
			}

			json_object_string_add(json_row, "source", src_str);
			json_object_string_add(json_row, "group", grp_str);
			json_object_string_add(json_row, "state", state_str);
			json_object_string_add(
				json_row, "joinState",
				pim_upstream_state2str(up->join_state));
			json_object_string_add(
				json_row, "regState",
				pim_reg_state2str(up->reg_state, state_str,
						  sizeof(state_str)));
			json_object_string_add(json_row, "upTime", uptime);
			json_object_string_add(json_row, "joinTimer",
					       join_timer);
			json_object_string_add(json_row, "resetTimer",
					       rs_timer);
			json_object_string_add(json_row, "keepaliveTimer",
					       ka_timer);
			json_object_string_add(json_row, "msdpRegTimer",
					       msdp_reg_timer);
			json_object_int_add(json_row, "refCount",
					    up->ref_count);
			json_object_int_add(json_row, "sptBit", up->sptbit);
			json_object_object_add(json_group, src_str, json_row);
		} else {
			ttable_add_row(tt,
				"%s|%pPAs|%pPAs|%s|%s|%s|%s|%s|%d",
				up->rpf.source_nexthop.interface
				? up->rpf.source_nexthop.interface->name
				: "Unknown",
				&up->sg.src, &up->sg.grp, state_str, uptime,
				join_timer, rs_timer, ka_timer, up->ref_count);
		}
	}
	/* Dump the generated table. */
	if (!json) {
		table = ttable_dump(tt, "\n");
		vty_out(vty, "%s\n", table);
		XFREE(MTYPE_TMP, table);
		ttable_del(tt);
	}
}

static void pim_show_join_desired_helper(struct pim_instance *pim,
					 struct vty *vty,
					 struct pim_upstream *up,
					 json_object *json, bool uj,
					 struct ttable *tt)
{
	json_object *json_group = NULL;
	json_object *json_row = NULL;

	if (uj) {
		char grp_str[PIM_ADDRSTRLEN];
		char src_str[PIM_ADDRSTRLEN];

		snprintfrr(grp_str, sizeof(grp_str), "%pPAs", &up->sg.grp);
		snprintfrr(src_str, sizeof(src_str), "%pPAs", &up->sg.src);

		json_object_object_get_ex(json, grp_str, &json_group);

		if (!json_group) {
			json_group = json_object_new_object();
			json_object_object_add(json, grp_str, json_group);
		}

		json_row = json_object_new_object();
		json_object_pim_upstream_add(json_row, up);
		json_object_string_add(json_row, "source", src_str);
		json_object_string_add(json_row, "group", grp_str);

		if (pim_upstream_evaluate_join_desired(pim, up))
			json_object_boolean_true_add(json_row,
						     "evaluateJoinDesired");

		json_object_object_add(json_group, src_str, json_row);

	} else {
		ttable_add_row(tt, "%pPAs|%pPAs|%s", &up->sg.src, &up->sg.grp,
			       pim_upstream_evaluate_join_desired(pim, up)
				       ? "yes"
				       : "no");
	}
}

void pim_show_join_desired(struct pim_instance *pim, struct vty *vty, bool uj)
{
	struct pim_upstream *up;
	struct ttable *tt = NULL;
	char *table = NULL;

	json_object *json = NULL;

	if (uj)
		json = json_object_new_object();
	else {
		/* Prepare table. */
		tt = ttable_new(&ttable_styles[TTSTYLE_BLANK]);
		ttable_add_row(tt, "Source|Group|EvalJD");
		tt->style.cell.rpad = 2;
		tt->style.corner = '+';
		ttable_restyle(tt);
	}

	frr_each (rb_pim_upstream, &pim->upstream_head, up) {
		/* scan all interfaces */
		pim_show_join_desired_helper(pim, vty, up, json, uj, tt);
	}

	if (uj)
		vty_json(vty, json);
	else {
		/* Dump the generated table. */
		table = ttable_dump(tt, "\n");
		vty_out(vty, "%s\n", table);
		XFREE(MTYPE_TMP, table);
		ttable_del(tt);
	}
}

void pim_show_upstream_rpf(struct pim_instance *pim, struct vty *vty, bool uj)
{
	struct pim_upstream *up;
	struct ttable *tt = NULL;
	char *table = NULL;
	json_object *json = NULL;
	json_object *json_group = NULL;
	json_object *json_row = NULL;

	if (uj)
		json = json_object_new_object();
	else {
		/* Prepare table. */
		tt = ttable_new(&ttable_styles[TTSTYLE_BLANK]);
		ttable_add_row(tt,
			       "Source|Group|RpfIface|RibNextHop|RpfAddress");
		tt->style.cell.rpad = 2;
		tt->style.corner = '+';
		ttable_restyle(tt);
	}

	frr_each (rb_pim_upstream, &pim->upstream_head, up) {
		struct pim_rpf *rpf;
		const char *rpf_ifname;

		rpf = &up->rpf;

		rpf_ifname =
			rpf->source_nexthop.interface ? rpf->source_nexthop
								.interface->name
						      : "<ifname?>";

		if (uj) {
			char grp_str[PIM_ADDRSTRLEN];
			char src_str[PIM_ADDRSTRLEN];

			snprintfrr(grp_str, sizeof(grp_str), "%pPAs",
				   &up->sg.grp);
			snprintfrr(src_str, sizeof(src_str), "%pPAs",
				   &up->sg.src);
			json_object_object_get_ex(json, grp_str, &json_group);

			if (!json_group) {
				json_group = json_object_new_object();
				json_object_object_add(json, grp_str,
						       json_group);
			}

			json_row = json_object_new_object();
			json_object_pim_upstream_add(json_row, up);
			json_object_string_add(json_row, "source", src_str);
			json_object_string_add(json_row, "group", grp_str);
			json_object_string_add(json_row, "rpfInterface",
					       rpf_ifname);
			json_object_string_addf(
				json_row, "ribNexthop", "%pPAs",
				&rpf->source_nexthop.mrib_nexthop_addr);
			json_object_string_addf(json_row, "rpfAddress", "%pPA",
						&rpf->rpf_addr);
			json_object_object_add(json_group, src_str, json_row);
		} else {
			ttable_add_row(tt, "%pPAs|%pPAs|%s|%pPA|%pPA",
				       &up->sg.src, &up->sg.grp, rpf_ifname,
				       &rpf->source_nexthop.mrib_nexthop_addr,
				       &rpf->rpf_addr);
		}
	}

	if (uj)
		vty_json(vty, json);
	else {
		/* Dump the generated table. */
		table = ttable_dump(tt, "\n");
		vty_out(vty, "%s\n", table);
		XFREE(MTYPE_TMP, table);
		ttable_del(tt);
	}
}

static void pim_show_join_helper(struct pim_interface *pim_ifp,
				 struct pim_ifchannel *ch, json_object *json,
				 time_t now, struct ttable *tt)
{
	json_object *json_iface = NULL;
	json_object *json_row = NULL;
	json_object *json_grp = NULL;
	pim_addr ifaddr;
	char uptime[10];
	char expire[10];
	char prune[10];

	ifaddr = pim_ifp->primary_address;

	pim_time_uptime_begin(uptime, sizeof(uptime), now, ch->ifjoin_creation);
	pim_time_timer_to_mmss(expire, sizeof(expire),
			       ch->t_ifjoin_expiry_timer);
	pim_time_timer_to_mmss(prune, sizeof(prune),
			       ch->t_ifjoin_prune_pending_timer);

	if (json) {
		char ch_grp_str[PIM_ADDRSTRLEN];

		json_object_object_get_ex(json, ch->interface->name,
					  &json_iface);

		if (!json_iface) {
			json_iface = json_object_new_object();
			json_object_pim_ifp_add(json_iface, ch->interface);
			json_object_object_add(json, ch->interface->name,
					       json_iface);
		}

		json_row = json_object_new_object();
		json_object_string_addf(json_row, "source", "%pPAs",
					&ch->sg.src);
		json_object_string_addf(json_row, "group", "%pPAs",
					&ch->sg.grp);
		json_object_string_add(json_row, "upTime", uptime);
		json_object_string_add(json_row, "expire", expire);
		json_object_string_add(json_row, "prune", prune);
		json_object_string_add(
			json_row, "channelJoinName",
			pim_ifchannel_ifjoin_name(ch->ifjoin_state, ch->flags));
		if (PIM_IF_FLAG_TEST_S_G_RPT(ch->flags))
			json_object_int_add(json_row, "sgRpt", 1);
		if (PIM_IF_FLAG_TEST_PROTO_PIM(ch->flags))
			json_object_int_add(json_row, "protocolPim", 1);
		if (PIM_IF_FLAG_TEST_PROTO_IGMP(ch->flags))
			json_object_int_add(json_row, "protocolIgmp", 1);
		snprintfrr(ch_grp_str, sizeof(ch_grp_str), "%pPAs",
			   &ch->sg.grp);
		json_object_object_get_ex(json_iface, ch_grp_str, &json_grp);
		if (!json_grp) {
			json_grp = json_object_new_object();
			json_object_object_addf(json_grp, json_row, "%pPAs",
						&ch->sg.src);
			json_object_object_addf(json_iface, json_grp, "%pPAs",
						&ch->sg.grp);
		} else
			json_object_object_addf(json_grp, json_row, "%pPAs",
						&ch->sg.src);
	} else {
		ttable_add_row(
			tt, "%s|%pPAs|%pPAs|%pPAs|%s|%s|%s|%s",
			ch->interface->name, &ifaddr, &ch->sg.src, &ch->sg.grp,
			pim_ifchannel_ifjoin_name(ch->ifjoin_state, ch->flags),
			uptime, expire, prune);
	}
}

int pim_show_join_cmd_helper(const char *vrf, struct vty *vty, pim_addr s_or_g,
			     pim_addr g, const char *json)
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
	pim = v->info;

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

int pim_show_join_vrf_all_cmd_helper(struct vty *vty, const char *json)
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

void pim_show_join(struct pim_instance *pim, struct vty *vty, pim_sgaddr *sg,
		   json_object *json)
{
	struct pim_interface *pim_ifp;
	struct pim_ifchannel *ch;
	struct interface *ifp;
	time_t now;
	struct ttable *tt = NULL;
	char *table = NULL;

	now = pim_time_monotonic_sec();

	if (!json) {
		/* Prepare table. */
		tt = ttable_new(&ttable_styles[TTSTYLE_BLANK]);
		ttable_add_row(
			tt,
			"Interface|Address|Source|Group|State|Uptime|Expire|Prune");
		tt->style.cell.rpad = 2;
		tt->style.corner = '+';
		ttable_restyle(tt);
	}

	FOR_ALL_INTERFACES (pim->vrf, ifp) {
		pim_ifp = ifp->info;
		if (!pim_ifp)
			continue;

		RB_FOREACH (ch, pim_ifchannel_rb, &pim_ifp->ifchannel_rb) {
			if (!pim_sgaddr_match(ch->sg, *sg))
				continue;

			pim_show_join_helper(pim_ifp, ch, json, now, tt);
		} /* scan interface channels */
	}
	/* Dump the generated table. */
	if (!json) {
		table = ttable_dump(tt, "\n");
		vty_out(vty, "%s\n", table);
		XFREE(MTYPE_TMP, table);
		ttable_del(tt);
	}
}

static void pim_show_jp_agg_helper(struct interface *ifp,
				   struct pim_neighbor *neigh,
				   struct pim_upstream *up, int is_join,
				   struct ttable *tt)
{
	ttable_add_row(tt, "%s|%pPAs|%pPAs|%pPAs|%s", ifp->name,
		       &neigh->source_addr, &up->sg.src, &up->sg.grp,
		       is_join ? "J" : "P");
}

int pim_show_jp_agg_list_cmd_helper(const char *vrf, struct vty *vty)
{
	struct vrf *v;
	struct pim_instance *pim;

	v = vrf_lookup_by_name(vrf ? vrf : VRF_DEFAULT_NAME);

	if (!v) {
		vty_out(vty, "%% Vrf specified: %s does not exist\n", vrf);
		return CMD_WARNING;
	}
	pim = v->info;

	if (!pim) {
		vty_out(vty, "%% Unable to find pim instance\n");
		return CMD_WARNING;
	}

	pim_show_jp_agg_list(pim, vty);

	return CMD_SUCCESS;
}

void pim_show_jp_agg_list(struct pim_instance *pim, struct vty *vty)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;
	struct listnode *n_node;
	struct pim_neighbor *neigh;
	struct listnode *jag_node;
	struct pim_jp_agg_group *jag;
	struct listnode *js_node;
	struct pim_jp_sources *js;
	struct ttable *tt;
	char *table;

	/* Prepare table. */
	tt = ttable_new(&ttable_styles[TTSTYLE_BLANK]);
	ttable_add_row(tt, "Interface|RPF Nbr|Source|Group|State");
	tt->style.cell.rpad = 2;
	tt->style.corner = '+';
	ttable_restyle(tt);

	FOR_ALL_INTERFACES (pim->vrf, ifp) {
		pim_ifp = ifp->info;
		if (!pim_ifp)
			continue;

		for (ALL_LIST_ELEMENTS_RO(pim_ifp->pim_neighbor_list, n_node,
					  neigh)) {
			for (ALL_LIST_ELEMENTS_RO(neigh->upstream_jp_agg,
						  jag_node, jag)) {
				for (ALL_LIST_ELEMENTS_RO(jag->sources, js_node,
							  js)) {
					pim_show_jp_agg_helper(ifp, neigh,
							       js->up,
							       js->is_join, tt);
				}
			}
		}
	}

	/* Dump the generated table. */
	table = ttable_dump(tt, "\n");
	vty_out(vty, "%s\n", table);
	XFREE(MTYPE_TMP, table);
	ttable_del(tt);
}

int pim_show_membership_cmd_helper(const char *vrf, struct vty *vty, bool uj)
{
	struct vrf *v;

	v = vrf_lookup_by_name(vrf ? vrf : VRF_DEFAULT_NAME);

	if (!v)
		return CMD_WARNING;

	pim_show_membership(v->info, vty, uj);

	return CMD_SUCCESS;
}

static void pim_show_membership_helper(struct vty *vty,
				       struct pim_interface *pim_ifp,
				       struct pim_ifchannel *ch,
				       struct json_object *json)
{
	json_object *json_iface = NULL;
	json_object *json_row = NULL;

	json_object_object_get_ex(json, ch->interface->name, &json_iface);
	if (!json_iface) {
		json_iface = json_object_new_object();
		json_object_pim_ifp_add(json_iface, ch->interface);
		json_object_object_add(json, ch->interface->name, json_iface);
	}

	json_row = json_object_new_object();
	json_object_string_addf(json_row, "source", "%pPAs", &ch->sg.src);
	json_object_string_addf(json_row, "group", "%pPAs", &ch->sg.grp);
	json_object_string_add(json_row, "localMembership",
			       ch->local_ifmembership == PIM_IFMEMBERSHIP_NOINFO
				       ? "NOINFO"
				       : "INCLUDE");
	json_object_object_addf(json_iface, json_row, "%pPAs", &ch->sg.grp);
}

void pim_show_membership(struct pim_instance *pim, struct vty *vty, bool uj)
{
	struct pim_interface *pim_ifp;
	struct pim_ifchannel *ch;
	struct interface *ifp;
	enum json_type type;
	json_object *json = NULL;
	json_object *json_tmp = NULL;
	struct ttable *tt = NULL;
	char *table = NULL;

	json = json_object_new_object();

	FOR_ALL_INTERFACES (pim->vrf, ifp) {
		pim_ifp = ifp->info;
		if (!pim_ifp)
			continue;

		RB_FOREACH (ch, pim_ifchannel_rb, &pim_ifp->ifchannel_rb) {
			pim_show_membership_helper(vty, pim_ifp, ch, json);
		} /* scan interface channels */
	}

	if (uj) {
		vty_json(vty, json);
	} else {
		/* Prepare table. */
		tt = ttable_new(&ttable_styles[TTSTYLE_BLANK]);
		ttable_add_row(tt, "Interface|Address|Source|Group|Membership");
		tt->style.cell.rpad = 2;
		tt->style.corner = '+';
		ttable_restyle(tt);

		/*
		 * Example of the json data we are traversing
		 *
		 * {
		 *   "swp3":{
		 *     "name":"swp3",
		 *     "state":"up",
		 *     "address":"10.1.20.1",
		 *     "index":5,
		 *     "flagMulticast":true,
		 *     "flagBroadcast":true,
		 *     "lanDelayEnabled":true,
		 *     "226.10.10.10":{
		 *       "source":"*",
		 *       "group":"226.10.10.10",
		 *       "localMembership":"INCLUDE"
		 *     }
		 *   }
		 * }
		 */

		/* foreach interface */
		json_object_object_foreach(json, key, val)
		{

			/* Find all of the keys where the val is an object. In
			 * the example
			 * above the only one is 226.10.10.10
			 */
			json_object_object_foreach(val, if_field_key,
						   if_field_val)
			{
				type = json_object_get_type(if_field_val);

				if (type == json_type_object) {
					const char *address, *source,
						*localMembership;

					json_object_object_get_ex(
						val, "address", &json_tmp);
					address = json_object_get_string(
						json_tmp);

					json_object_object_get_ex(if_field_val,
								  "source",
								  &json_tmp);
					source = json_object_get_string(
						json_tmp);

					json_object_object_get_ex(
						if_field_val, "localMembership",
						&json_tmp);
					localMembership =
						json_object_get_string(
							json_tmp);

					ttable_add_row(tt, "%s|%s|%s|%s|%s",
						       key, address, source,
						       if_field_key,
						       localMembership);
				}
			}
		}
		json_object_free(json);
		/* Dump the generated table. */
		table = ttable_dump(tt, "\n");
		vty_out(vty, "%s\n", table);
		XFREE(MTYPE_TMP, table);
		ttable_del(tt);
	}
}

static void pim_show_channel_helper(struct pim_instance *pim,
				    struct pim_interface *pim_ifp,
				    struct pim_ifchannel *ch, json_object *json,
				    bool uj, struct ttable *tt)
{
	struct pim_upstream *up = ch->upstream;
	json_object *json_group = NULL;
	json_object *json_row = NULL;

	if (uj) {
		char grp_str[PIM_ADDRSTRLEN];

		snprintfrr(grp_str, sizeof(grp_str), "%pPAs", &up->sg.grp);
		json_object_object_get_ex(json, grp_str, &json_group);

		if (!json_group) {
			json_group = json_object_new_object();
			json_object_object_add(json, grp_str, json_group);
		}

		json_row = json_object_new_object();
		json_object_pim_upstream_add(json_row, up);
		json_object_string_add(json_row, "interface",
				       ch->interface->name);
		json_object_string_addf(json_row, "source", "%pPAs",
					&up->sg.src);
		json_object_string_addf(json_row, "group", "%pPAs",
					&up->sg.grp);

		if (pim_macro_ch_lost_assert(ch))
			json_object_boolean_true_add(json_row, "lostAssert");

		if (pim_macro_chisin_joins(ch))
			json_object_boolean_true_add(json_row, "joins");

		if (pim_macro_chisin_pim_include(ch))
			json_object_boolean_true_add(json_row, "pimInclude");

		if (pim_upstream_evaluate_join_desired(pim, up))
			json_object_boolean_true_add(json_row,
						     "evaluateJoinDesired");

		json_object_object_addf(json_group, json_row, "%pPAs",
					&up->sg.src);

	} else {
		ttable_add_row(tt, "%s|%pPAs|%pPAs|%s|%s|%s|%s|%s",
			       ch->interface->name, &up->sg.src, &up->sg.grp,
			       pim_macro_ch_lost_assert(ch) ? "yes" : "no",
			       pim_macro_chisin_joins(ch) ? "yes" : "no",
			       pim_macro_chisin_pim_include(ch) ? "yes" : "no",
			       PIM_UPSTREAM_FLAG_TEST_DR_JOIN_DESIRED(up->flags)
				       ? "yes"
				       : "no",
			       pim_upstream_evaluate_join_desired(pim, up)
				       ? "yes"
				       : "no");
	}
}

void pim_show_channel(struct pim_instance *pim, struct vty *vty, bool uj)
{
	struct pim_interface *pim_ifp;
	struct pim_ifchannel *ch;
	struct interface *ifp;
	struct ttable *tt = NULL;
	json_object *json = NULL;
	char *table = NULL;

	if (uj)
		json = json_object_new_object();
	else {
		/* Prepare table. */
		tt = ttable_new(&ttable_styles[TTSTYLE_BLANK]);
		ttable_add_row(
			tt,
			"Interface|Source|Group|LostAssert|Joins|PimInclude|JoinDesired|EvalJD");
		tt->style.cell.rpad = 2;
		tt->style.corner = '+';
		ttable_restyle(tt);
	}

	/* scan per-interface (S,G) state */
	FOR_ALL_INTERFACES (pim->vrf, ifp) {
		pim_ifp = ifp->info;
		if (!pim_ifp)
			continue;

		RB_FOREACH (ch, pim_ifchannel_rb, &pim_ifp->ifchannel_rb) {
			/* scan all interfaces */
			pim_show_channel_helper(pim, pim_ifp, ch, json, uj, tt);
		}
	}

	if (uj)
		vty_json(vty, json);
	else {
		/* Dump the generated table. */
		table = ttable_dump(tt, "\n");
		vty_out(vty, "%s\n", table);
		XFREE(MTYPE_TMP, table);
		ttable_del(tt);
	}
}

int pim_show_channel_cmd_helper(const char *vrf, struct vty *vty, bool uj)
{
	struct vrf *v;

	v = vrf_lookup_by_name(vrf ? vrf : VRF_DEFAULT_NAME);

	if (!v)
		return CMD_WARNING;

	pim_show_channel(v->info, vty, uj);

	return CMD_SUCCESS;
}

int pim_show_interface_cmd_helper(const char *vrf, struct vty *vty, bool uj,
				  bool mlag, const char *interface)
{
	struct vrf *v;
	json_object *json_parent = NULL;

	v = vrf_lookup_by_name(vrf ? vrf : VRF_DEFAULT_NAME);

	if (!v)
		return CMD_WARNING;

	if (uj)
		json_parent = json_object_new_object();

	if (interface)
		pim_show_interfaces_single(v->info, vty, interface, mlag,
					   json_parent);
	else
		pim_show_interfaces(v->info, vty, mlag, json_parent);

	if (uj)
		vty_json(vty, json_parent);

	return CMD_SUCCESS;
}

int pim_show_interface_vrf_all_cmd_helper(struct vty *vty, bool uj, bool mlag,
					  const char *interface)
{
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
						   mlag, json_vrf);
		else
			pim_show_interfaces(v->info, vty, mlag, json_vrf);

		if (uj)
			json_object_object_add(json_parent, v->name, json_vrf);
	}
	if (uj)
		vty_json(vty, json_parent);

	return CMD_SUCCESS;
}

void pim_show_interfaces(struct pim_instance *pim, struct vty *vty, bool mlag,
			 json_object *json)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;
	struct pim_upstream *up;
	int fhr = 0;
	int pim_nbrs = 0;
	int pim_ifchannels = 0;
	bool uj = true;
	struct ttable *tt = NULL;
	char *table = NULL;
	json_object *json_row = NULL;
	json_object *json_tmp;

	if (!json) {
		uj = false;
		json = json_object_new_object();
	}

	FOR_ALL_INTERFACES (pim->vrf, ifp) {
		pim_ifp = ifp->info;

		if (!pim_ifp)
			continue;

		if (mlag == true && pim_ifp->activeactive == false)
			continue;

		pim_nbrs = pim_ifp->pim_neighbor_list->count;
		pim_ifchannels = pim_if_ifchannel_count(pim_ifp);
		fhr = 0;

		frr_each (rb_pim_upstream, &pim->upstream_head, up)
			if (ifp == up->rpf.source_nexthop.interface)
				if (up->flags & PIM_UPSTREAM_FLAG_MASK_FHR)
					fhr++;

		json_row = json_object_new_object();
		json_object_pim_ifp_add(json_row, ifp);
		json_object_int_add(json_row, "pimNeighbors", pim_nbrs);
		json_object_int_add(json_row, "pimIfChannels", pim_ifchannels);
		json_object_int_add(json_row, "firstHopRouterCount", fhr);
		json_object_string_addf(json_row, "pimDesignatedRouter",
					"%pPAs", &pim_ifp->pim_dr_addr);

		if (!pim_addr_cmp(pim_ifp->pim_dr_addr,
				  pim_ifp->primary_address))
			json_object_boolean_true_add(
				json_row, "pimDesignatedRouterLocal");

		json_object_object_add(json, ifp->name, json_row);
	}

	if (!uj) {

		/* Prepare table. */
		tt = ttable_new(&ttable_styles[TTSTYLE_BLANK]);
		ttable_add_row(
			tt,
			"Interface|State|Address|PIM Nbrs|PIM DR|FHR|IfChannels");
		tt->style.cell.rpad = 2;
		tt->style.corner = '+';
		ttable_restyle(tt);

		json_object_object_foreach(json, key, val)
		{
			const char *state, *address, *pimdr;
			int neighbors, firsthpr, pimifchnl;

			json_object_object_get_ex(val, "state", &json_tmp);
			state = json_object_get_string(json_tmp);

			json_object_object_get_ex(val, "address", &json_tmp);
			address = json_object_get_string(json_tmp);

			json_object_object_get_ex(val, "pimNeighbors",
						  &json_tmp);
			neighbors = json_object_get_int(json_tmp);

			if (json_object_object_get_ex(
				    val, "pimDesignatedRouterLocal",
				    &json_tmp)) {
				pimdr = "local";
			} else {
				json_object_object_get_ex(
					val, "pimDesignatedRouter", &json_tmp);
				pimdr = json_object_get_string(json_tmp);
			}

			json_object_object_get_ex(val, "firstHopRouter",
						  &json_tmp);
			firsthpr = json_object_get_int(json_tmp);

			json_object_object_get_ex(val, "pimIfChannels",
						  &json_tmp);
			pimifchnl = json_object_get_int(json_tmp);

			ttable_add_row(tt, "%s|%s|%s|%d|%s|%d|%d", key, state,
				       address, neighbors, pimdr, firsthpr,
				       pimifchnl);
		}
		json_object_free(json);

		/* Dump the generated table. */
		table = ttable_dump(tt, "\n");
		vty_out(vty, "%s\n", table);
		XFREE(MTYPE_TMP, table);

		ttable_del(tt);
	}
}

void pim_show_interfaces_single(struct pim_instance *pim, struct vty *vty,
				const char *ifname, bool mlag,
				json_object *json)
{
	pim_addr ifaddr;
	struct interface *ifp;
	struct listnode *neighnode;
	struct pim_interface *pim_ifp;
	struct pim_neighbor *neigh;
	struct pim_upstream *up;
	time_t now;
	char dr_str[PIM_ADDRSTRLEN];
	char dr_uptime[10];
	char expire[10];
	char grp_str[PIM_ADDRSTRLEN];
	char hello_period[10];
	char hello_timer[10];
	char neigh_src_str[PIM_ADDRSTRLEN];
	char src_str[PIM_ADDRSTRLEN];
	char stat_uptime[10];
	char uptime[10];
	int found_ifname = 0;
	int print_header;
	json_object *json_row = NULL;
	json_object *json_pim_neighbor = NULL;
	json_object *json_pim_neighbors = NULL;
	json_object *json_group = NULL;
	json_object *json_group_source = NULL;
	json_object *json_fhr_sources = NULL;
	struct pim_secondary_addr *sec_addr;
	struct listnode *sec_node;

	now = pim_time_monotonic_sec();

	FOR_ALL_INTERFACES (pim->vrf, ifp) {
		pim_ifp = ifp->info;

		if (!pim_ifp)
			continue;

		if (mlag == true && pim_ifp->activeactive == false)
			continue;

		if (strcmp(ifname, "detail") && strcmp(ifname, ifp->name))
			continue;

		found_ifname = 1;
		ifaddr = pim_ifp->primary_address;
		snprintfrr(dr_str, sizeof(dr_str), "%pPAs",
			   &pim_ifp->pim_dr_addr);
		pim_time_uptime_begin(dr_uptime, sizeof(dr_uptime), now,
				      pim_ifp->pim_dr_election_last);
		pim_time_timer_to_hhmmss(hello_timer, sizeof(hello_timer),
					 pim_ifp->t_pim_hello_timer);
		pim_time_mmss(hello_period, sizeof(hello_period),
			      pim_ifp->pim_hello_period);
		pim_time_uptime(stat_uptime, sizeof(stat_uptime),
				now - pim_ifp->pim_ifstat_start);

		if (json) {
			json_row = json_object_new_object();
			json_object_pim_ifp_add(json_row, ifp);

			if (!pim_addr_is_any(pim_ifp->update_source)) {
				json_object_string_addf(
					json_row, "useSource", "%pPAs",
					&pim_ifp->update_source);
			}
			if (pim_ifp->sec_addr_list) {
				json_object *sec_list = NULL;

				sec_list = json_object_new_array();
				for (ALL_LIST_ELEMENTS_RO(
					     pim_ifp->sec_addr_list, sec_node,
					     sec_addr)) {
					json_object_array_add(
						sec_list,
						json_object_new_stringf(
							"%pFXh",
							&sec_addr->addr));
				}
				json_object_object_add(json_row,
						       "secondaryAddressList",
						       sec_list);
			}

			if (pim_ifp->pim_passive_enable)
				json_object_boolean_true_add(json_row,
							     "passive");

			/* PIM neighbors */
			if (pim_ifp->pim_neighbor_list->count) {
				json_pim_neighbors = json_object_new_object();

				for (ALL_LIST_ELEMENTS_RO(
					     pim_ifp->pim_neighbor_list,
					     neighnode, neigh)) {
					json_pim_neighbor =
						json_object_new_object();
					snprintfrr(neigh_src_str,
						   sizeof(neigh_src_str),
						   "%pPAs",
						   &neigh->source_addr);
					pim_time_uptime(uptime, sizeof(uptime),
							now - neigh->creation);
					pim_time_timer_to_hhmmss(
						expire, sizeof(expire),
						neigh->t_expire_timer);

					json_object_string_add(
						json_pim_neighbor, "address",
						neigh_src_str);
					json_object_string_add(
						json_pim_neighbor, "upTime",
						uptime);
					json_object_string_add(
						json_pim_neighbor, "holdtime",
						expire);

					json_object_object_add(
						json_pim_neighbors,
						neigh_src_str,
						json_pim_neighbor);
				}

				json_object_object_add(json_row, "neighbors",
						       json_pim_neighbors);
			}

			json_object_string_add(json_row, "drAddress", dr_str);
			json_object_int_add(json_row, "drPriority",
					    pim_ifp->pim_dr_priority);
			json_object_string_add(json_row, "drUptime", dr_uptime);
			json_object_int_add(json_row, "drElections",
					    pim_ifp->pim_dr_election_count);
			json_object_int_add(json_row, "drChanges",
					    pim_ifp->pim_dr_election_changes);

			/* FHR */
			frr_each (rb_pim_upstream, &pim->upstream_head, up) {
				if (ifp != up->rpf.source_nexthop.interface)
					continue;

				if (!(up->flags & PIM_UPSTREAM_FLAG_MASK_FHR))
					continue;

				if (!json_fhr_sources)
					json_fhr_sources =
						json_object_new_object();

				snprintfrr(grp_str, sizeof(grp_str), "%pPAs",
					   &up->sg.grp);
				snprintfrr(src_str, sizeof(src_str), "%pPAs",
					   &up->sg.src);
				pim_time_uptime(uptime, sizeof(uptime),
						now - up->state_transition);

				/*
				 * Does this group live in json_fhr_sources?
				 * If not create it.
				 */
				json_object_object_get_ex(json_fhr_sources,
							  grp_str, &json_group);

				if (!json_group) {
					json_group = json_object_new_object();
					json_object_object_add(json_fhr_sources,
							       grp_str,
							       json_group);
				}

				json_group_source = json_object_new_object();
				json_object_string_add(json_group_source,
						       "source", src_str);
				json_object_string_add(json_group_source,
						       "group", grp_str);
				json_object_string_add(json_group_source,
						       "upTime", uptime);
				json_object_object_add(json_group, src_str,
						       json_group_source);
			}

			if (json_fhr_sources) {
				json_object_object_add(json_row,
						       "firstHopRouter",
						       json_fhr_sources);
			}

			json_object_int_add(json_row, "helloPeriod",
					    pim_ifp->pim_hello_period);
			json_object_int_add(json_row, "holdTime",
					    PIM_IF_DEFAULT_HOLDTIME(pim_ifp));
			json_object_string_add(json_row, "helloTimer",
					       hello_timer);
			json_object_string_add(json_row, "helloStatStart",
					       stat_uptime);
			json_object_int_add(json_row, "helloReceived",
					    pim_ifp->pim_ifstat_hello_recv);
			json_object_int_add(json_row, "helloReceivedFailed",
					    pim_ifp->pim_ifstat_hello_recvfail);
			json_object_int_add(json_row, "helloSend",
					    pim_ifp->pim_ifstat_hello_sent);
			json_object_int_add(json_row, "hellosendFailed",
					    pim_ifp->pim_ifstat_hello_sendfail);
			json_object_int_add(json_row, "helloGenerationId",
					    pim_ifp->pim_generation_id);

			json_object_int_add(
				json_row, "effectivePropagationDelay",
				pim_if_effective_propagation_delay_msec(ifp));
			json_object_int_add(
				json_row, "effectiveOverrideInterval",
				pim_if_effective_override_interval_msec(ifp));
			json_object_int_add(
				json_row, "joinPruneOverrideInterval",
				pim_if_jp_override_interval_msec(ifp));

			json_object_int_add(
				json_row, "propagationDelay",
				pim_ifp->pim_propagation_delay_msec);
			json_object_int_add(
				json_row, "propagationDelayHighest",
				pim_ifp->pim_neighbors_highest_propagation_delay_msec);
			json_object_int_add(
				json_row, "overrideInterval",
				pim_ifp->pim_override_interval_msec);
			json_object_int_add(
				json_row, "overrideIntervalHighest",
				pim_ifp->pim_neighbors_highest_override_interval_msec);
			if (pim_ifp->bsm_enable)
				json_object_boolean_true_add(json_row,
							     "bsmEnabled");
			if (pim_ifp->ucast_bsm_accept)
				json_object_boolean_true_add(json_row,
							     "ucastBsmEnabled");
			json_object_object_add(json, ifp->name, json_row);

		} else {
			vty_out(vty, "Interface  : %s\n", ifp->name);
			vty_out(vty, "State      : %s\n",
				if_is_up(ifp) ? "up" : "down");
			if (!pim_addr_is_any(pim_ifp->update_source)) {
				vty_out(vty, "Use Source : %pPAs\n",
					&pim_ifp->update_source);
			}
			if (pim_ifp->sec_addr_list) {
				vty_out(vty, "Address    : %pPAs (primary)\n",
					&ifaddr);
				for (ALL_LIST_ELEMENTS_RO(
					     pim_ifp->sec_addr_list, sec_node,
					     sec_addr))
					vty_out(vty, "             %pFX\n",
						&sec_addr->addr);
			} else {
				vty_out(vty, "Address    : %pPAs\n", &ifaddr);
			}

			if (pim_ifp->pim_passive_enable)
				vty_out(vty, "Passive    : %s\n",
					(pim_ifp->pim_passive_enable) ? "yes"
								      : "no");

			vty_out(vty, "\n");

			/* PIM neighbors */
			print_header = 1;

			for (ALL_LIST_ELEMENTS_RO(pim_ifp->pim_neighbor_list,
						  neighnode, neigh)) {

				if (print_header) {
					vty_out(vty, "PIM Neighbors\n");
					vty_out(vty, "-------------\n");
					print_header = 0;
				}

				snprintfrr(neigh_src_str, sizeof(neigh_src_str),
					   "%pPAs", &neigh->source_addr);
				pim_time_uptime(uptime, sizeof(uptime),
						now - neigh->creation);
				pim_time_timer_to_hhmmss(expire, sizeof(expire),
							 neigh->t_expire_timer);
				vty_out(vty,
					"%-15s : up for %s, holdtime expires in %s\n",
					neigh_src_str, uptime, expire);
			}

			if (!print_header) {
				vty_out(vty, "\n");
				vty_out(vty, "\n");
			}

			vty_out(vty, "Designated Router\n");
			vty_out(vty, "-----------------\n");
			vty_out(vty, "Address   : %s\n", dr_str);
			vty_out(vty, "Priority  : %u(%d)\n",
				pim_ifp->pim_dr_priority,
				pim_ifp->pim_dr_num_nondrpri_neighbors);
			vty_out(vty, "Uptime    : %s\n", dr_uptime);
			vty_out(vty, "Elections : %d\n",
				pim_ifp->pim_dr_election_count);
			vty_out(vty, "Changes   : %d\n",
				pim_ifp->pim_dr_election_changes);
			vty_out(vty, "\n");
			vty_out(vty, "\n");

			/* FHR */
			print_header = 1;
			frr_each (rb_pim_upstream, &pim->upstream_head, up) {
				if (!up->rpf.source_nexthop.interface)
					continue;

				if (strcmp(ifp->name,
					   up->rpf.source_nexthop
						   .interface->name) != 0)
					continue;

				if (!(up->flags & PIM_UPSTREAM_FLAG_MASK_FHR))
					continue;

				if (print_header) {
					vty_out(vty,
						"FHR - First Hop Router\n");
					vty_out(vty,
						"----------------------\n");
					print_header = 0;
				}

				pim_time_uptime(uptime, sizeof(uptime),
						now - up->state_transition);
				vty_out(vty,
					"%pPAs : %pPAs is a source, uptime is %s\n",
					&up->sg.grp, &up->sg.src, uptime);
			}

			if (!print_header) {
				vty_out(vty, "\n");
				vty_out(vty, "\n");
			}

			vty_out(vty, "Hellos\n");
			vty_out(vty, "------\n");
			vty_out(vty, "Period         : %d\n",
				pim_ifp->pim_hello_period);
			vty_out(vty, "HoldTime       : %d\n",
				PIM_IF_DEFAULT_HOLDTIME(pim_ifp));
			vty_out(vty, "Timer          : %s\n", hello_timer);
			vty_out(vty, "StatStart      : %s\n", stat_uptime);
			vty_out(vty, "Receive        : %d\n",
				pim_ifp->pim_ifstat_hello_recv);
			vty_out(vty, "Receive Failed : %d\n",
				pim_ifp->pim_ifstat_hello_recvfail);
			vty_out(vty, "Send           : %d\n",
				pim_ifp->pim_ifstat_hello_sent);
			vty_out(vty, "Send Failed    : %d\n",
				pim_ifp->pim_ifstat_hello_sendfail);
			vty_out(vty, "Generation ID  : %08x\n",
				pim_ifp->pim_generation_id);
			vty_out(vty, "\n");
			vty_out(vty, "\n");

			pim_print_ifp_flags(vty, ifp);

			vty_out(vty, "Join Prune Interval\n");
			vty_out(vty, "-------------------\n");
			vty_out(vty, "LAN Delay                    : %s\n",
				pim_if_lan_delay_enabled(ifp) ? "yes" : "no");
			vty_out(vty, "Effective Propagation Delay  : %d msec\n",
				pim_if_effective_propagation_delay_msec(ifp));
			vty_out(vty, "Effective Override Interval  : %d msec\n",
				pim_if_effective_override_interval_msec(ifp));
			vty_out(vty, "Join Prune Override Interval : %d msec\n",
				pim_if_jp_override_interval_msec(ifp));
			vty_out(vty, "\n");
			vty_out(vty, "\n");

			vty_out(vty, "LAN Prune Delay\n");
			vty_out(vty, "---------------\n");
			vty_out(vty, "Propagation Delay           : %d msec\n",
				pim_ifp->pim_propagation_delay_msec);
			vty_out(vty, "Propagation Delay (Highest) : %d msec\n",
				pim_ifp->pim_neighbors_highest_propagation_delay_msec);
			vty_out(vty, "Override Interval           : %d msec\n",
				pim_ifp->pim_override_interval_msec);
			vty_out(vty, "Override Interval (Highest) : %d msec\n",
				pim_ifp->pim_neighbors_highest_override_interval_msec);
			vty_out(vty, "\n");
			vty_out(vty, "\n");

			vty_out(vty, "BSM Status\n");
			vty_out(vty, "----------\n");
			vty_out(vty, "Bsm Enabled          : %s\n",
				pim_ifp->bsm_enable ? "yes" : "no");
			vty_out(vty, "Unicast Bsm Enabled  : %s\n",
				pim_ifp->ucast_bsm_accept ? "yes" : "no");
			vty_out(vty, "\n");
			vty_out(vty, "\n");
		}
	}

	if (!found_ifname && !json)
		vty_out(vty, "%% No such interface\n");
}

void ip_pim_ssm_show_group_range(struct pim_instance *pim, struct vty *vty,
				 bool uj)
{
	struct pim_ssm *ssm = pim->ssm_info;
	const char *range_str =
		ssm->plist_name ? ssm->plist_name : PIM_SSM_STANDARD_RANGE;

	if (uj) {
		json_object *json;

		json = json_object_new_object();
		json_object_string_add(json, "ssmGroups", range_str);
		vty_json(vty, json);
	} else
		vty_out(vty, "SSM group range : %s\n", range_str);
}

struct vty_pnc_cache_walk_data {
	struct vty *vty;
	struct pim_instance *pim;
};

struct json_pnc_cache_walk_data {
	json_object *json_obj;
	struct pim_instance *pim;
};

static int pim_print_vty_pnc_cache_walkcb(struct hash_bucket *bucket, void *arg)
{
	struct pim_nexthop_cache *pnc = bucket->data;
	struct vty_pnc_cache_walk_data *cwd = arg;
	struct vty *vty = cwd->vty;
	struct pim_instance *pim = cwd->pim;
	struct nexthop *nh_node = NULL;
	ifindex_t first_ifindex;
	struct interface *ifp = NULL;
	struct ttable *tt = NULL;
	char *table = NULL;

	/* Prepare table. */
	tt = ttable_new(&ttable_styles[TTSTYLE_BLANK]);
	ttable_add_row(tt, "Address|Interface|Nexthop");
	tt->style.cell.rpad = 2;
	tt->style.corner = '+';
	ttable_restyle(tt);

	for (nh_node = pnc->nexthop; nh_node; nh_node = nh_node->next) {
		first_ifindex = nh_node->ifindex;

		ifp = if_lookup_by_index(first_ifindex, pim->vrf->vrf_id);

#if PIM_IPV == 4
		ttable_add_row(tt, "%pPA|%s|%pI4", &pnc->rpf.rpf_addr,
			       ifp ? ifp->name : "NULL", &nh_node->gate.ipv4);
#else
		ttable_add_row(tt, "%pPA|%s|%pI6", &pnc->rpf.rpf_addr,
			       ifp ? ifp->name : "NULL", &nh_node->gate.ipv6);
#endif
	}
	/* Dump the generated table. */
	table = ttable_dump(tt, "\n");
	vty_out(vty, "%s\n", table);
	XFREE(MTYPE_TMP, table);
	ttable_del(tt);

	return CMD_SUCCESS;
}

static int pim_print_json_pnc_cache_walkcb(struct hash_bucket *backet,
					   void *arg)
{
	struct pim_nexthop_cache *pnc = backet->data;
	struct json_pnc_cache_walk_data *cwd = arg;
	struct pim_instance *pim = cwd->pim;
	struct nexthop *nh_node = NULL;
	ifindex_t first_ifindex;
	struct interface *ifp = NULL;
	char addr_str[PIM_ADDRSTRLEN];
	json_object *json_row = NULL;
	json_object *json_ifp = NULL;
	json_object *json_arr = NULL;
	struct pim_interface *pim_ifp = NULL;
	bool pim_enable = false;

	for (nh_node = pnc->nexthop; nh_node; nh_node = nh_node->next) {
		first_ifindex = nh_node->ifindex;
		ifp = if_lookup_by_index(first_ifindex, pim->vrf->vrf_id);
		snprintfrr(addr_str, sizeof(addr_str), "%pPA",
			   &pnc->rpf.rpf_addr);
		json_object_object_get_ex(cwd->json_obj, addr_str, &json_row);
		if (!json_row) {
			json_row = json_object_new_object();
			json_object_string_addf(json_row, "address", "%pPA",
						&pnc->rpf.rpf_addr);
			json_object_object_addf(cwd->json_obj, json_row, "%pPA",
						&pnc->rpf.rpf_addr);
			json_arr = json_object_new_array();
			json_object_object_add(json_row, "nexthops", json_arr);
		}
		json_ifp = json_object_new_object();
		json_object_string_add(json_ifp, "interface",
				       ifp ? ifp->name : "NULL");

		if (ifp)
			pim_ifp = ifp->info;

		if (pim_ifp && pim_ifp->pim_enable)
			pim_enable = true;

		json_object_boolean_add(json_ifp, "pimEnabled", pim_enable);
#if PIM_IPV == 4
		json_object_string_addf(json_ifp, "nexthop", "%pI4",
					&nh_node->gate.ipv4);
#else
		json_object_string_addf(json_ifp, "nexthop", "%pI6",
					&nh_node->gate.ipv6);
#endif
		json_object_array_add(json_arr, json_ifp);
	}
	return CMD_SUCCESS;
}

int pim_show_nexthop_lookup_cmd_helper(const char *vrf, struct vty *vty,
				       pim_addr source, pim_addr group)
{
	int result = 0;
	pim_addr vif_source;
	struct prefix grp;
	struct pim_nexthop nexthop;
	struct vrf *v;

	v = vrf_lookup_by_name(vrf ? vrf : VRF_DEFAULT_NAME);

	if (!v)
		return CMD_WARNING;

#if PIM_IPV == 4
	if (pim_is_group_224_4(source)) {
		vty_out(vty,
			"Invalid argument. Expected Valid Source Address.\n");
		return CMD_WARNING;
	}

	if (!pim_is_group_224_4(group)) {
		vty_out(vty,
			"Invalid argument. Expected Valid Multicast Group Address.\n");
		return CMD_WARNING;
	}
#endif

	if (!pim_rp_set_upstream_addr(v->info, &vif_source, source, group))
		return CMD_SUCCESS;

	pim_addr_to_prefix(&grp, group);
	memset(&nexthop, 0, sizeof(nexthop));

	result =
		pim_ecmp_nexthop_lookup(v->info, &nexthop, vif_source, &grp, 0);

	if (!result) {
		vty_out(vty,
			"Nexthop Lookup failed, no usable routes returned.\n");
		return CMD_SUCCESS;
	}

	vty_out(vty, "Group %pFXh --- Nexthop %pPAs Interface %s\n", &grp,
		&nexthop.mrib_nexthop_addr, nexthop.interface->name);

	return CMD_SUCCESS;
}

int pim_show_nexthop_cmd_helper(const char *vrf, struct vty *vty, bool uj)
{
	struct vrf *v;

	v = vrf_lookup_by_name(vrf ? vrf : VRF_DEFAULT_NAME);

	if (!v)
		return CMD_WARNING;

	pim_show_nexthop(v->info, vty, uj);

	return CMD_SUCCESS;
}

void pim_show_nexthop(struct pim_instance *pim, struct vty *vty, bool uj)
{
	struct vty_pnc_cache_walk_data cwd;
	struct json_pnc_cache_walk_data jcwd;

	cwd.vty = vty;
	cwd.pim = pim;
	jcwd.pim = pim;

	if (uj) {
		jcwd.json_obj = json_object_new_object();
	} else {
		vty_out(vty, "Number of registered addresses: %lu\n",
			pim->rpf_hash->count);
	}

	if (uj) {
		hash_walk(pim->rpf_hash, pim_print_json_pnc_cache_walkcb,
			  &jcwd);
		vty_json(vty, jcwd.json_obj);
	} else
		hash_walk(pim->rpf_hash, pim_print_vty_pnc_cache_walkcb, &cwd);
}

int pim_show_neighbors_cmd_helper(const char *vrf, struct vty *vty,
				  const char *json, const char *interface)
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

int pim_show_neighbors_vrf_all_cmd_helper(struct vty *vty, const char *json,
					  const char *interface)
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

void pim_show_neighbors_single(struct pim_instance *pim, struct vty *vty,
			       const char *neighbor, json_object *json)
{
	struct listnode *neighnode;
	struct interface *ifp;
	struct pim_interface *pim_ifp;
	struct pim_neighbor *neigh;
	time_t now;
	int found_neighbor = 0;
	int option_address_list;
	int option_dr_priority;
	int option_generation_id;
	int option_holdtime;
	int option_lan_prune_delay;
	int option_t_bit;
	char uptime[10];
	char expire[10];
	char neigh_src_str[PIM_ADDRSTRLEN];

	json_object *json_ifp = NULL;
	json_object *json_row = NULL;

	now = pim_time_monotonic_sec();

	FOR_ALL_INTERFACES (pim->vrf, ifp) {
		pim_ifp = ifp->info;

		if (!pim_ifp)
			continue;

		if (pim_ifp->pim_sock_fd < 0)
			continue;

		for (ALL_LIST_ELEMENTS_RO(pim_ifp->pim_neighbor_list, neighnode,
					  neigh)) {
			snprintfrr(neigh_src_str, sizeof(neigh_src_str),
				   "%pPAs", &neigh->source_addr);

			/*
			 * The user can specify either the interface name or the
			 * PIM neighbor IP.
			 * If this pim_ifp matches neither then skip.
			 */
			if (strcmp(neighbor, "detail") &&
			    strcmp(neighbor, ifp->name) &&
			    strcmp(neighbor, neigh_src_str))
				continue;

			found_neighbor = 1;
			pim_time_uptime(uptime, sizeof(uptime),
					now - neigh->creation);
			pim_time_timer_to_hhmmss(expire, sizeof(expire),
						 neigh->t_expire_timer);

			option_address_list = 0;
			option_dr_priority = 0;
			option_generation_id = 0;
			option_holdtime = 0;
			option_lan_prune_delay = 0;
			option_t_bit = 0;

			if (PIM_OPTION_IS_SET(neigh->hello_options,
					      PIM_OPTION_MASK_ADDRESS_LIST))
				option_address_list = 1;

			if (PIM_OPTION_IS_SET(neigh->hello_options,
					      PIM_OPTION_MASK_DR_PRIORITY))
				option_dr_priority = 1;

			if (PIM_OPTION_IS_SET(neigh->hello_options,
					      PIM_OPTION_MASK_GENERATION_ID))
				option_generation_id = 1;

			if (PIM_OPTION_IS_SET(neigh->hello_options,
					      PIM_OPTION_MASK_HOLDTIME))
				option_holdtime = 1;

			if (PIM_OPTION_IS_SET(neigh->hello_options,
					      PIM_OPTION_MASK_LAN_PRUNE_DELAY))
				option_lan_prune_delay = 1;

			if (PIM_OPTION_IS_SET(
				    neigh->hello_options,
				    PIM_OPTION_MASK_CAN_DISABLE_JOIN_SUPPRESSION))
				option_t_bit = 1;

			if (json) {

				/* Does this ifp live in json? If not create it
				 */
				json_object_object_get_ex(json, ifp->name,
							  &json_ifp);

				if (!json_ifp) {
					json_ifp = json_object_new_object();
					json_object_pim_ifp_add(json_ifp, ifp);
					json_object_object_add(json, ifp->name,
							       json_ifp);
				}

				json_row = json_object_new_object();
				json_object_string_add(json_row, "interface",
						       ifp->name);
				json_object_string_add(json_row, "address",
						       neigh_src_str);
				json_object_string_add(json_row, "upTime",
						       uptime);
				json_object_string_add(json_row, "holdtime",
						       expire);
				json_object_int_add(json_row, "drPriority",
						    neigh->dr_priority);
				json_object_int_add(json_row, "generationId",
						    neigh->generation_id);

				if (option_address_list)
					json_object_boolean_true_add(
						json_row,
						"helloOptionAddressList");

				if (option_dr_priority)
					json_object_boolean_true_add(
						json_row,
						"helloOptionDrPriority");

				if (option_generation_id)
					json_object_boolean_true_add(
						json_row,
						"helloOptionGenerationId");

				if (option_holdtime)
					json_object_boolean_true_add(
						json_row,
						"helloOptionHoldtime");

				if (option_lan_prune_delay)
					json_object_boolean_true_add(
						json_row,
						"helloOptionLanPruneDelay");

				if (option_t_bit)
					json_object_boolean_true_add(
						json_row, "helloOptionTBit");

				json_object_object_add(json_ifp, neigh_src_str,
						       json_row);

			} else {
				vty_out(vty, "Interface : %s\n", ifp->name);
				vty_out(vty, "Neighbor  : %s\n", neigh_src_str);
				vty_out(vty,
					"    Uptime                         : %s\n",
					uptime);
				vty_out(vty,
					"    Holdtime                       : %s\n",
					expire);
				vty_out(vty,
					"    DR Priority                    : %d\n",
					neigh->dr_priority);
				vty_out(vty,
					"    Generation ID                  : %08x\n",
					neigh->generation_id);
				vty_out(vty,
					"    Override Interval (msec)       : %d\n",
					neigh->override_interval_msec);
				vty_out(vty,
					"    Propagation Delay (msec)       : %d\n",
					neigh->propagation_delay_msec);
				vty_out(vty,
					"    Hello Option - Address List    : %s\n",
					option_address_list ? "yes" : "no");
				vty_out(vty,
					"    Hello Option - DR Priority     : %s\n",
					option_dr_priority ? "yes" : "no");
				vty_out(vty,
					"    Hello Option - Generation ID   : %s\n",
					option_generation_id ? "yes" : "no");
				vty_out(vty,
					"    Hello Option - Holdtime        : %s\n",
					option_holdtime ? "yes" : "no");
				vty_out(vty,
					"    Hello Option - LAN Prune Delay : %s\n",
					option_lan_prune_delay ? "yes" : "no");
				vty_out(vty,
					"    Hello Option - T-bit           : %s\n",
					option_t_bit ? "yes" : "no");
				bfd_sess_show(vty, json_ifp,
					      neigh->bfd_session);
				vty_out(vty, "\n");
			}
		}
	}

	if (!found_neighbor && !json)
		vty_out(vty, "%% No such interface or neighbor\n");
}

void pim_show_neighbors(struct pim_instance *pim, struct vty *vty,
			json_object *json)
{
	struct listnode *neighnode;
	struct interface *ifp;
	struct pim_interface *pim_ifp;
	struct pim_neighbor *neigh;
	struct ttable *tt = NULL;
	char *table = NULL;
	time_t now;
	char uptime[10];
	char expire[10];
	char neigh_src_str[PIM_ADDRSTRLEN];
	json_object *json_ifp_rows = NULL;
	json_object *json_row = NULL;

	now = pim_time_monotonic_sec();

	if (!json) {
		/* Prepare table. */
		tt = ttable_new(&ttable_styles[TTSTYLE_BLANK]);
		ttable_add_row(tt, "Interface|Neighbor|Uptime|Holdtime|DR Pri");
		tt->style.cell.rpad = 2;
		tt->style.corner = '+';
		ttable_restyle(tt);
	}

	FOR_ALL_INTERFACES (pim->vrf, ifp) {
		pim_ifp = ifp->info;

		if (!pim_ifp)
			continue;

		if (pim_ifp->pim_sock_fd < 0)
			continue;

		if (json)
			json_ifp_rows = json_object_new_object();

		for (ALL_LIST_ELEMENTS_RO(pim_ifp->pim_neighbor_list, neighnode,
					  neigh)) {
			snprintfrr(neigh_src_str, sizeof(neigh_src_str),
				   "%pPAs", &neigh->source_addr);
			pim_time_uptime(uptime, sizeof(uptime),
					now - neigh->creation);
			pim_time_timer_to_hhmmss(expire, sizeof(expire),
						 neigh->t_expire_timer);

			if (json) {
				json_row = json_object_new_object();
				json_object_string_add(json_row, "interface",
						       ifp->name);
				json_object_string_add(json_row, "neighbor",
						       neigh_src_str);
				json_object_string_add(json_row, "upTime",
						       uptime);
				json_object_string_add(json_row, "holdTime",
						       expire);
				json_object_int_add(json_row, "holdTimeMax",
						    neigh->holdtime);
				json_object_int_add(json_row, "drPriority",
						    neigh->dr_priority);
				json_object_object_add(json_ifp_rows,
						       neigh_src_str, json_row);

			} else {
				ttable_add_row(tt, "%s|%pPAs|%s|%s|%d",
					       ifp->name, &neigh->source_addr,
					       uptime, expire,
					       neigh->dr_priority);
			}
		}

		if (json) {
			json_object_object_add(json, ifp->name, json_ifp_rows);
			json_ifp_rows = NULL;
		}
	}
	/* Dump the generated table. */
	if (!json) {
		table = ttable_dump(tt, "\n");
		vty_out(vty, "%s\n", table);
		XFREE(MTYPE_TMP, table);
		ttable_del(tt);
	}
}

int gm_process_query_max_response_time_cmd(struct vty *vty,
					   const char *qmrt_str)
{
	const struct lyd_node *pim_enable_dnode;

	pim_enable_dnode = yang_dnode_getf(vty->candidate_config->dnode,
					   FRR_PIM_ENABLE_XPATH, VTY_CURR_XPATH,
					   FRR_PIM_AF_XPATH_VAL);

	if (!pim_enable_dnode) {
		nb_cli_enqueue_change(vty, "./enable", NB_OP_MODIFY, "true");
	} else {
		if (!yang_dnode_get_bool(pim_enable_dnode, "."))
			nb_cli_enqueue_change(vty, "./enable", NB_OP_MODIFY,
					      "true");
	}

	nb_cli_enqueue_change(vty, "./query-max-response-time", NB_OP_MODIFY,
			      qmrt_str);
	return nb_cli_apply_changes(vty, FRR_GMP_INTERFACE_XPATH,
				    FRR_PIM_AF_XPATH_VAL);
}

int gm_process_no_query_max_response_time_cmd(struct vty *vty)
{
	nb_cli_enqueue_change(vty, "./query-max-response-time", NB_OP_DESTROY,
			      NULL);
	return nb_cli_apply_changes(vty, FRR_GMP_INTERFACE_XPATH,
				    FRR_PIM_AF_XPATH_VAL);
}

int gm_process_last_member_query_count_cmd(struct vty *vty,
					   const char *lmqc_str)
{
	const struct lyd_node *pim_enable_dnode;

	pim_enable_dnode = yang_dnode_getf(vty->candidate_config->dnode,
					   FRR_PIM_ENABLE_XPATH, VTY_CURR_XPATH,
					   FRR_PIM_AF_XPATH_VAL);
	if (!pim_enable_dnode) {
		nb_cli_enqueue_change(vty, "./enable", NB_OP_MODIFY, "true");
	} else {
		if (!yang_dnode_get_bool(pim_enable_dnode, "."))
			nb_cli_enqueue_change(vty, "./enable", NB_OP_MODIFY,
					      "true");
	}

	nb_cli_enqueue_change(vty, "./robustness-variable", NB_OP_MODIFY,
			      lmqc_str);
	return nb_cli_apply_changes(vty, FRR_GMP_INTERFACE_XPATH,
				    FRR_PIM_AF_XPATH_VAL);
}

int gm_process_no_last_member_query_count_cmd(struct vty *vty)
{
	nb_cli_enqueue_change(vty, "./robustness-variable", NB_OP_DESTROY,
			      NULL);
	return nb_cli_apply_changes(vty, FRR_GMP_INTERFACE_XPATH,
				    FRR_PIM_AF_XPATH_VAL);
}

int gm_process_last_member_query_interval_cmd(struct vty *vty,
					      const char *lmqi_str)
{
	const struct lyd_node *pim_enable_dnode;

	pim_enable_dnode = yang_dnode_getf(vty->candidate_config->dnode,
					   FRR_PIM_ENABLE_XPATH, VTY_CURR_XPATH,
					   FRR_PIM_AF_XPATH_VAL);
	if (!pim_enable_dnode) {
		nb_cli_enqueue_change(vty, "./enable", NB_OP_MODIFY, "true");
	} else {
		if (!yang_dnode_get_bool(pim_enable_dnode, "."))
			nb_cli_enqueue_change(vty, "./enable", NB_OP_MODIFY,
					      "true");
	}

	nb_cli_enqueue_change(vty, "./last-member-query-interval", NB_OP_MODIFY,
			      lmqi_str);
	return nb_cli_apply_changes(vty, FRR_GMP_INTERFACE_XPATH,
				    FRR_PIM_AF_XPATH_VAL);
}

int gm_process_no_last_member_query_interval_cmd(struct vty *vty)
{
	nb_cli_enqueue_change(vty, "./last-member-query-interval",
			      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, FRR_GMP_INTERFACE_XPATH,
				    FRR_PIM_AF_XPATH_VAL);
}

int pim_process_ssmpingd_cmd(struct vty *vty, enum nb_operation operation,
			     const char *src_str)
{
	const char *vrfname;
	char ssmpingd_ip_xpath[XPATH_MAXLEN];
	char ssmpingd_src_ip_xpath[XPATH_MAXLEN];
	int printed;

	vrfname = pim_cli_get_vrf_name(vty);
	if (vrfname == NULL)
		return CMD_WARNING_CONFIG_FAILED;

	snprintf(ssmpingd_ip_xpath, sizeof(ssmpingd_ip_xpath),
		 FRR_PIM_VRF_XPATH, "frr-pim:pimd", "pim", vrfname,
		 FRR_PIM_AF_XPATH_VAL);
	printed = snprintf(ssmpingd_src_ip_xpath, sizeof(ssmpingd_src_ip_xpath),
			   "%s/ssm-pingd-source-ip[.='%s']", ssmpingd_ip_xpath,
			   src_str);
	if (printed >= (int)sizeof(ssmpingd_src_ip_xpath)) {
		vty_out(vty, "Xpath too long (%d > %u)", printed + 1,
			XPATH_MAXLEN);
		return CMD_WARNING_CONFIG_FAILED;
	}

	nb_cli_enqueue_change(vty, ssmpingd_src_ip_xpath, operation, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

int pim_process_bsm_cmd(struct vty *vty)
{
	const struct lyd_node *gm_enable_dnode;

	gm_enable_dnode = yang_dnode_getf(vty->candidate_config->dnode,
					  FRR_GMP_ENABLE_XPATH, VTY_CURR_XPATH,
					  FRR_PIM_AF_XPATH_VAL);
	if (!gm_enable_dnode)
		nb_cli_enqueue_change(vty, "./pim-enable", NB_OP_MODIFY,
				      "true");
	else {
		if (!yang_dnode_get_bool(gm_enable_dnode, "."))
			nb_cli_enqueue_change(vty, "./pim-enable", NB_OP_MODIFY,
					      "true");
	}

	nb_cli_enqueue_change(vty, "./bsm", NB_OP_MODIFY, "true");

	return nb_cli_apply_changes(vty, FRR_PIM_INTERFACE_XPATH,
				    FRR_PIM_AF_XPATH_VAL);
}

int pim_process_no_bsm_cmd(struct vty *vty)
{
	nb_cli_enqueue_change(vty, "./bsm", NB_OP_MODIFY, "false");

	return nb_cli_apply_changes(vty, FRR_PIM_INTERFACE_XPATH,
				    FRR_PIM_AF_XPATH_VAL);
}

int pim_process_unicast_bsm_cmd(struct vty *vty)
{
	const struct lyd_node *gm_enable_dnode;

	gm_enable_dnode = yang_dnode_getf(vty->candidate_config->dnode,
					  FRR_GMP_ENABLE_XPATH, VTY_CURR_XPATH,
					  FRR_PIM_AF_XPATH_VAL);
	if (!gm_enable_dnode)
		nb_cli_enqueue_change(vty, "./pim-enable", NB_OP_MODIFY,
				      "true");
	else {
		if (!yang_dnode_get_bool(gm_enable_dnode, "."))
			nb_cli_enqueue_change(vty, "./pim-enable", NB_OP_MODIFY,
					      "true");
	}

	nb_cli_enqueue_change(vty, "./unicast-bsm", NB_OP_MODIFY, "true");

	return nb_cli_apply_changes(vty, FRR_PIM_INTERFACE_XPATH,
				    FRR_PIM_AF_XPATH_VAL);
}

int pim_process_no_unicast_bsm_cmd(struct vty *vty)
{
	nb_cli_enqueue_change(vty, "./unicast-bsm", NB_OP_MODIFY, "false");

	return nb_cli_apply_changes(vty, FRR_PIM_INTERFACE_XPATH,
				    FRR_PIM_AF_XPATH_VAL);
}

static void show_scan_oil_stats(struct pim_instance *pim, struct vty *vty,
				time_t now)
{
	char uptime_scan_oil[10];
	char uptime_mroute_add[10];
	char uptime_mroute_del[10];

	pim_time_uptime_begin(uptime_scan_oil, sizeof(uptime_scan_oil), now,
			      pim->scan_oil_last);
	pim_time_uptime_begin(uptime_mroute_add, sizeof(uptime_mroute_add), now,
			      pim->mroute_add_last);
	pim_time_uptime_begin(uptime_mroute_del, sizeof(uptime_mroute_del), now,
			      pim->mroute_del_last);

	vty_out(vty,
		"Scan OIL - Last: %s  Events: %lld\n"
		"MFC Add  - Last: %s  Events: %lld\n"
		"MFC Del  - Last: %s  Events: %lld\n",
		uptime_scan_oil, (long long)pim->scan_oil_events,
		uptime_mroute_add, (long long)pim->mroute_add_events,
		uptime_mroute_del, (long long)pim->mroute_del_events);
}

void show_multicast_interfaces(struct pim_instance *pim, struct vty *vty,
			       json_object *json)
{
	struct interface *ifp;
	struct ttable *tt = NULL;
	char *table = NULL;
	json_object *json_row = NULL;

	vty_out(vty, "\n");

	if (!json) {
		/* Prepare table. */
		tt = ttable_new(&ttable_styles[TTSTYLE_BLANK]);
		ttable_add_row(
			tt,
			"Interface|Address|ifi|Vif|PktsIn|PktsOut|BytesIn|BytesOut");
		tt->style.cell.rpad = 2;
		tt->style.corner = '+';
		ttable_restyle(tt);
	}

	FOR_ALL_INTERFACES (pim->vrf, ifp) {
		struct pim_interface *pim_ifp;
#if PIM_IPV == 4
		struct sioc_vif_req vreq;
#else
		struct sioc_mif_req6 vreq;
#endif

		pim_ifp = ifp->info;

		if (!pim_ifp)
			continue;

		memset(&vreq, 0, sizeof(vreq));
#if PIM_IPV == 4
		vreq.vifi = pim_ifp->mroute_vif_index;
		if (ioctl(pim->mroute_socket, SIOCGETVIFCNT, &vreq)) {
			zlog_warn(
				"ioctl(SIOCGETVIFCNT=%lu) failure for interface %s vif_index=%d: errno=%d: %s",
				(unsigned long)SIOCGETVIFCNT, ifp->name,
				pim_ifp->mroute_vif_index, errno,
				safe_strerror(errno));
		}
#else
		vreq.mifi = pim_ifp->mroute_vif_index;
		if (ioctl(pim->mroute_socket, SIOCGETMIFCNT_IN6, &vreq)) {
			zlog_warn(
				"ioctl(SIOCGETMIFCNT_IN6=%lu) failure for interface %s vif_index=%d: errno=%d: %s",
				(unsigned long)SIOCGETMIFCNT_IN6, ifp->name,
				pim_ifp->mroute_vif_index, errno,
				safe_strerror(errno));
		}
#endif

		if (json) {
			json_row = json_object_new_object();
			json_object_string_add(json_row, "name", ifp->name);
			json_object_string_add(json_row, "state",
					       if_is_up(ifp) ? "up" : "down");
			json_object_string_addf(json_row, "address", "%pPA",
						&pim_ifp->primary_address);
			json_object_int_add(json_row, "ifIndex", ifp->ifindex);
			json_object_int_add(json_row, "vif",
					    pim_ifp->mroute_vif_index);
			json_object_int_add(json_row, "pktsIn",
					    (unsigned long)vreq.icount);
			json_object_int_add(json_row, "pktsOut",
					    (unsigned long)vreq.ocount);
			json_object_int_add(json_row, "bytesIn",
					    (unsigned long)vreq.ibytes);
			json_object_int_add(json_row, "bytesOut",
					    (unsigned long)vreq.obytes);
			json_object_object_add(json, ifp->name, json_row);
		} else {
			ttable_add_row(tt, "%s|%pPAs|%d|%d|%lu|%lu|%lu|%lu",
				       ifp->name, &pim_ifp->primary_address,
				       ifp->ifindex, pim_ifp->mroute_vif_index,
				       (unsigned long)vreq.icount,
				       (unsigned long)vreq.ocount,
				       (unsigned long)vreq.ibytes,
				       (unsigned long)vreq.obytes);
		}
	}
	/* Dump the generated table. */
	if (!json) {
		table = ttable_dump(tt, "\n");
		vty_out(vty, "%s\n", table);
		XFREE(MTYPE_TMP, table);
		ttable_del(tt);
	}
}

void pim_cmd_show_ip_multicast_helper(struct pim_instance *pim, struct vty *vty)
{
	struct vrf *vrf = pim->vrf;
	time_t now = pim_time_monotonic_sec();
	char uptime[10];
	char mlag_role[80];

	pim = vrf->info;

	vty_out(vty, "Router MLAG Role: %s\n",
		mlag_role2str(router->mlag_role, mlag_role, sizeof(mlag_role)));
	vty_out(vty, "Mroute socket descriptor:");

	vty_out(vty, " %d(%s)\n", pim->mroute_socket, vrf->name);
	vty_out(vty, "PIM Register socket descriptor:");
	vty_out(vty, " %d(%s)\n", pim->reg_sock, vrf->name);

	pim_time_uptime(uptime, sizeof(uptime),
			now - pim->mroute_socket_creation);
	vty_out(vty, "Mroute socket uptime: %s\n", uptime);

	vty_out(vty, "\n");

	pim_zebra_zclient_update(vty);
	pim_zlookup_show_ip_multicast(vty);

	vty_out(vty, "\n");
	vty_out(vty, "Maximum highest VifIndex: %d\n", PIM_MAX_USABLE_VIFS);

	vty_out(vty, "\n");
	vty_out(vty, "Upstream Join Timer: %d secs\n", router->t_periodic);
	vty_out(vty, "Join/Prune Holdtime: %d secs\n", PIM_JP_HOLDTIME);
	vty_out(vty, "PIM ECMP: %s\n", pim->ecmp_enable ? "Enable" : "Disable");
	vty_out(vty, "PIM ECMP Rebalance: %s\n",
		pim->ecmp_rebalance_enable ? "Enable" : "Disable");

	vty_out(vty, "\n");

	pim_show_rpf_refresh_stats(vty, pim, now, NULL);

	vty_out(vty, "\n");

	show_scan_oil_stats(pim, vty, now);

	show_multicast_interfaces(pim, vty, NULL);
}

void show_mroute(struct pim_instance *pim, struct vty *vty, pim_sgaddr *sg,
		 bool fill, json_object *json)
{
	struct listnode *node;
	struct channel_oil *c_oil;
	struct static_route *s_route;
	struct ttable *tt = NULL;
	char *table = NULL;
	time_t now;
	json_object *json_group = NULL;
	json_object *json_source = NULL;
	json_object *json_oil = NULL;
	json_object *json_ifp_out = NULL;
	int found_oif;
	int first;
	char grp_str[PIM_ADDRSTRLEN];
	char src_str[PIM_ADDRSTRLEN];
	char in_ifname[IFNAMSIZ + 1];
	char out_ifname[IFNAMSIZ + 1];
	int oif_vif_index;
	struct interface *ifp_in;
	char proto[100];
	char state_str[PIM_REG_STATE_STR_LEN];
	char mroute_uptime[10];

	if (!json) {
		vty_out(vty, "IP Multicast Routing Table\n");
		vty_out(vty, "Flags: S - Sparse, C - Connected, P - Pruned\n");
		vty_out(vty,
			"       R - SGRpt Pruned, F - Register flag, T - SPT-bit set\n");

		/* Prepare table. */
		tt = ttable_new(&ttable_styles[TTSTYLE_BLANK]);
		ttable_add_row(
			tt, "Source|Group|Flags|Proto|Input|Output|TTL|Uptime");
		tt->style.cell.rpad = 2;
		tt->style.corner = '+';
		ttable_restyle(tt);
	}

	now = pim_time_monotonic_sec();

	/* print list of PIM and IGMP routes */
	frr_each (rb_pim_oil, &pim->channel_oil_head, c_oil) {
		found_oif = 0;
		first = 1;
		if (!c_oil->installed)
			continue;

		if (!pim_addr_is_any(sg->grp) &&
		    pim_addr_cmp(sg->grp, *oil_mcastgrp(c_oil)))
			continue;
		if (!pim_addr_is_any(sg->src) &&
		    pim_addr_cmp(sg->src, *oil_origin(c_oil)))
			continue;

		snprintfrr(grp_str, sizeof(grp_str), "%pPAs",
			   oil_mcastgrp(c_oil));
		snprintfrr(src_str, sizeof(src_str), "%pPAs",
			   oil_origin(c_oil));

		strlcpy(state_str, "S", sizeof(state_str));
		/* When a non DR receives a igmp join, it creates a (*,G)
		 * channel_oil without any upstream creation
		 */
		if (c_oil->up) {
			if (PIM_UPSTREAM_FLAG_TEST_SRC_IGMP(c_oil->up->flags))
				strlcat(state_str, "C", sizeof(state_str));
			if (pim_upstream_is_sg_rpt(c_oil->up))
				strlcat(state_str, "R", sizeof(state_str));
			if (PIM_UPSTREAM_FLAG_TEST_FHR(c_oil->up->flags))
				strlcat(state_str, "F", sizeof(state_str));
			if (c_oil->up->sptbit == PIM_UPSTREAM_SPTBIT_TRUE)
				strlcat(state_str, "T", sizeof(state_str));
		}
		if (pim_channel_oil_empty(c_oil))
			strlcat(state_str, "P", sizeof(state_str));

		ifp_in = pim_if_find_by_vif_index(pim, *oil_incoming_vif(c_oil));

		if (ifp_in)
			strlcpy(in_ifname, ifp_in->name, sizeof(in_ifname));
		else
			strlcpy(in_ifname, "<iif?>", sizeof(in_ifname));


		pim_time_uptime(mroute_uptime, sizeof(mroute_uptime),
				now - c_oil->mroute_creation);

		if (json) {

			/* Find the group, create it if it doesn't exist */
			json_object_object_get_ex(json, grp_str, &json_group);

			if (!json_group) {
				json_group = json_object_new_object();
				json_object_object_add(json, grp_str,
						       json_group);
			}

			/* Find the source nested under the group, create it if
			 * it doesn't exist
			 */
			json_object_object_get_ex(json_group, src_str,
						  &json_source);

			if (!json_source) {
				json_source = json_object_new_object();
				json_object_object_add(json_group, src_str,
						       json_source);
			}

			/* Find the inbound interface nested under the source,
			 * create it if it doesn't exist
			 */
			json_object_string_add(json_source, "source", src_str);
			json_object_string_add(json_source, "group", grp_str);
			json_object_int_add(json_source, "installed",
					    c_oil->installed);
			json_object_int_add(json_source, "refCount",
					    c_oil->oil_ref_count);
			json_object_int_add(json_source, "oilSize",
					    c_oil->oil_size);
			json_object_int_add(json_source, "oilInheritedRescan",
					    c_oil->oil_inherited_rescan);
			json_object_string_add(json_source, "iif", in_ifname);
			json_object_string_add(json_source, "upTime",
					       mroute_uptime);
			json_oil = NULL;
		}

		for (oif_vif_index = 0; oif_vif_index < MAXVIFS;
		     ++oif_vif_index) {
			struct interface *ifp_out;
			int ttl;

			ttl = oil_if_has(c_oil, oif_vif_index);
			if (ttl < 1)
				continue;

			/* do not display muted OIFs */
			if (c_oil->oif_flags[oif_vif_index] & PIM_OIF_FLAG_MUTE)
				continue;

			if (*oil_incoming_vif(c_oil) == oif_vif_index &&
			    !pim_mroute_allow_iif_in_oil(c_oil, oif_vif_index))
				continue;

			ifp_out = pim_if_find_by_vif_index(pim, oif_vif_index);
			found_oif = 1;

			if (ifp_out)
				strlcpy(out_ifname, ifp_out->name,
					sizeof(out_ifname));
			else
				strlcpy(out_ifname, "<oif?>",
					sizeof(out_ifname));

			if (json) {
				json_ifp_out = json_object_new_object();
				json_object_string_add(json_ifp_out, "source",
						       src_str);
				json_object_string_add(json_ifp_out, "group",
						       grp_str);

				if (c_oil->oif_flags[oif_vif_index] &
				    PIM_OIF_FLAG_PROTO_PIM)
					json_object_boolean_true_add(
						json_ifp_out, "protocolPim");

				if (c_oil->oif_flags[oif_vif_index] &
				    PIM_OIF_FLAG_PROTO_GM)
#if PIM_IPV == 4
					json_object_boolean_true_add(
						json_ifp_out, "protocolIgmp");
#else
					json_object_boolean_true_add(
						json_ifp_out, "protocolMld");
#endif

				if (c_oil->oif_flags[oif_vif_index] &
				    PIM_OIF_FLAG_PROTO_VXLAN)
					json_object_boolean_true_add(
						json_ifp_out, "protocolVxlan");

				if (c_oil->oif_flags[oif_vif_index] &
				    PIM_OIF_FLAG_PROTO_STAR)
					json_object_boolean_true_add(
						json_ifp_out,
						"protocolInherited");

				json_object_string_add(json_ifp_out,
						       "inboundInterface",
						       in_ifname);
				json_object_int_add(json_ifp_out, "iVifI",
						    *oil_incoming_vif(c_oil));
				json_object_string_add(json_ifp_out,
						       "outboundInterface",
						       out_ifname);
				json_object_int_add(json_ifp_out, "oVifI",
						    oif_vif_index);
				json_object_int_add(json_ifp_out, "ttl", ttl);
				json_object_string_add(json_ifp_out, "upTime",
						       mroute_uptime);
				json_object_string_add(json_source, "flags",
						       state_str);
				if (!json_oil) {
					json_oil = json_object_new_object();
					json_object_object_add(json_source,
							       "oil", json_oil);
				}
				json_object_object_add(json_oil, out_ifname,
						       json_ifp_out);
			} else {
				proto[0] = '\0';
				if (c_oil->oif_flags[oif_vif_index] &
				    PIM_OIF_FLAG_PROTO_PIM) {
					strlcpy(proto, "PIM", sizeof(proto));
				}

				if (c_oil->oif_flags[oif_vif_index] &
				    PIM_OIF_FLAG_PROTO_GM) {
#if PIM_IPV == 4
					strlcpy(proto, "IGMP", sizeof(proto));
#else
					strlcpy(proto, "MLD", sizeof(proto));
#endif
				}

				if (c_oil->oif_flags[oif_vif_index] &
				    PIM_OIF_FLAG_PROTO_VXLAN) {
					strlcpy(proto, "VxLAN", sizeof(proto));
				}

				if (c_oil->oif_flags[oif_vif_index] &
				    PIM_OIF_FLAG_PROTO_STAR) {
					strlcpy(proto, "STAR", sizeof(proto));
				}

				ttable_add_row(tt, "%s|%s|%s|%s|%s|%s|%d|%s",
					       src_str, grp_str, state_str,
					       proto, in_ifname, out_ifname,
					       ttl, mroute_uptime);

				if (first) {
					src_str[0] = '\0';
					grp_str[0] = '\0';
					in_ifname[0] = '\0';
					state_str[0] = '\0';
					mroute_uptime[0] = '\0';
					first = 0;
				}
			}
		}

		if (!json && !found_oif) {
			ttable_add_row(tt, "%pPAs|%pPAs|%s|%s|%s|%s|%d|%s",
				       oil_origin(c_oil), oil_mcastgrp(c_oil),
				       state_str, "none", in_ifname, "none", 0,
				       "--:--:--");
		}
	}

	/* Print list of static routes */
	for (ALL_LIST_ELEMENTS_RO(pim->static_routes, node, s_route)) {
		first = 1;

		if (!s_route->c_oil.installed)
			continue;

		snprintfrr(grp_str, sizeof(grp_str), "%pPAs", &s_route->group);
		snprintfrr(src_str, sizeof(src_str), "%pPAs", &s_route->source);
		ifp_in = pim_if_find_by_vif_index(pim, s_route->iif);
		found_oif = 0;

		if (ifp_in)
			strlcpy(in_ifname, ifp_in->name, sizeof(in_ifname));
		else
			strlcpy(in_ifname, "<iif?>", sizeof(in_ifname));

		if (json) {

			/* Find the group, create it if it doesn't exist */
			json_object_object_get_ex(json, grp_str, &json_group);

			if (!json_group) {
				json_group = json_object_new_object();
				json_object_object_add(json, grp_str,
						       json_group);
			}

			/* Find the source nested under the group, create it if
			 * it doesn't exist
			 */
			json_object_object_get_ex(json_group, src_str,
						  &json_source);

			if (!json_source) {
				json_source = json_object_new_object();
				json_object_object_add(json_group, src_str,
						       json_source);
			}

			json_object_string_add(json_source, "iif", in_ifname);
			json_oil = NULL;
		} else {
			strlcpy(proto, "STATIC", sizeof(proto));
		}

		for (oif_vif_index = 0; oif_vif_index < MAXVIFS;
		     ++oif_vif_index) {
			struct interface *ifp_out;
			char oif_uptime[10];
			int ttl;

			ttl = s_route->oif_ttls[oif_vif_index];
			if (ttl < 1)
				continue;

			ifp_out = pim_if_find_by_vif_index(pim, oif_vif_index);
			pim_time_uptime(
				oif_uptime, sizeof(oif_uptime),
				now - s_route->c_oil
						.oif_creation[oif_vif_index]);
			found_oif = 1;

			if (ifp_out)
				strlcpy(out_ifname, ifp_out->name,
					sizeof(out_ifname));
			else
				strlcpy(out_ifname, "<oif?>",
					sizeof(out_ifname));

			if (json) {
				json_ifp_out = json_object_new_object();
				json_object_string_add(json_ifp_out, "source",
						       src_str);
				json_object_string_add(json_ifp_out, "group",
						       grp_str);
				json_object_boolean_true_add(json_ifp_out,
							     "protocolStatic");
				json_object_string_add(json_ifp_out,
						       "inboundInterface",
						       in_ifname);
				json_object_int_add(json_ifp_out, "iVifI",
						    *oil_incoming_vif(
							    &s_route->c_oil));
				json_object_string_add(json_ifp_out,
						       "outboundInterface",
						       out_ifname);
				json_object_int_add(json_ifp_out, "oVifI",
						    oif_vif_index);
				json_object_int_add(json_ifp_out, "ttl", ttl);
				json_object_string_add(json_ifp_out, "upTime",
						       oif_uptime);
				if (!json_oil) {
					json_oil = json_object_new_object();
					json_object_object_add(json_source,
							       "oil", json_oil);
				}
				json_object_object_add(json_oil, out_ifname,
						       json_ifp_out);
			} else {
				ttable_add_row(
					tt, "%pPAs|%pPAs|%s|%s|%s|%s|%d|%s",
					&s_route->source, &s_route->group, "-",
					proto, in_ifname, out_ifname, ttl,
					oif_uptime);
				if (first && !fill) {
					src_str[0] = '\0';
					grp_str[0] = '\0';
					in_ifname[0] = '\0';
					first = 0;
				}
			}
		}

		if (!json && !found_oif) {
			ttable_add_row(tt, "%pPAs|%pPAs|%s|%s|%s|%s|%d|%s",
				       &s_route->source, &s_route->group, "-",
				       proto, in_ifname, "none", 0, "--:--:--");
		}
	}
	/* Dump the generated table. */
	if (!json) {
		table = ttable_dump(tt, "\n");
		vty_out(vty, "%s\n", table);
		XFREE(MTYPE_TMP, table);
		ttable_del(tt);
	}
}

static void show_mroute_count_per_channel_oil(struct channel_oil *c_oil,
					      json_object *json,
					      struct ttable *tt)
{
	json_object *json_group = NULL;
	json_object *json_source = NULL;

	if (!c_oil->installed)
		return;

	pim_mroute_update_counters(c_oil);

	if (json) {
		char group_str[PIM_ADDRSTRLEN];
		char source_str[PIM_ADDRSTRLEN];

		snprintfrr(group_str, sizeof(group_str), "%pPAs",
			   oil_mcastgrp(c_oil));
		snprintfrr(source_str, sizeof(source_str), "%pPAs",
			   oil_origin(c_oil));

		json_object_object_get_ex(json, group_str, &json_group);

		if (!json_group) {
			json_group = json_object_new_object();
			json_object_object_add(json, group_str, json_group);
		}

		json_source = json_object_new_object();
		json_object_object_add(json_group, source_str, json_source);
		json_object_int_add(json_source, "lastUsed",
				    c_oil->cc.lastused / 100);
		json_object_int_add(json_source, "packets", c_oil->cc.pktcnt);
		json_object_int_add(json_source, "bytes", c_oil->cc.bytecnt);
		json_object_int_add(json_source, "wrongIf", c_oil->cc.wrong_if);

	} else {
		ttable_add_row(tt, "%pPAs|%pPAs|%llu|%ld|%ld|%ld",
			       oil_origin(c_oil), oil_mcastgrp(c_oil),
			       c_oil->cc.lastused / 100,
			       c_oil->cc.pktcnt - c_oil->cc.origpktcnt,
			       c_oil->cc.bytecnt - c_oil->cc.origbytecnt,
			       c_oil->cc.wrong_if - c_oil->cc.origwrong_if);
	}
}

void show_mroute_count(struct pim_instance *pim, struct vty *vty,
		       json_object *json)
{
	struct listnode *node;
	struct channel_oil *c_oil;
	struct static_route *sr;
	struct ttable *tt = NULL;
	char *table = NULL;

	if (!json) {
		vty_out(vty, "\n");

		/* Prepare table. */
		tt = ttable_new(&ttable_styles[TTSTYLE_BLANK]);
		ttable_add_row(tt,
			       "Source|Group|LastUsed|Packets|Bytes|WrongIf");
		tt->style.cell.rpad = 2;
		tt->style.corner = '+';
		ttable_restyle(tt);
	}

	/* Print PIM and IGMP route counts */
	frr_each (rb_pim_oil, &pim->channel_oil_head, c_oil)
		show_mroute_count_per_channel_oil(c_oil, json, tt);

	for (ALL_LIST_ELEMENTS_RO(pim->static_routes, node, sr))
		show_mroute_count_per_channel_oil(&sr->c_oil, json, tt);

	/* Dump the generated table. */
	if (!json) {
		table = ttable_dump(tt, "\n");
		vty_out(vty, "%s\n", table);
		XFREE(MTYPE_TMP, table);
		ttable_del(tt);
	}
}

void show_mroute_summary(struct pim_instance *pim, struct vty *vty,
			 json_object *json)
{
	struct listnode *node;
	struct channel_oil *c_oil;
	struct static_route *s_route;
	uint32_t starg_sw_mroute_cnt = 0;
	uint32_t sg_sw_mroute_cnt = 0;
	uint32_t starg_hw_mroute_cnt = 0;
	uint32_t sg_hw_mroute_cnt = 0;
	json_object *json_starg = NULL;
	json_object *json_sg = NULL;

	if (!json)
		vty_out(vty, "Mroute Type    Installed/Total\n");

	frr_each (rb_pim_oil, &pim->channel_oil_head, c_oil) {
		if (!c_oil->installed) {
			if (pim_addr_is_any(*oil_origin(c_oil)))
				starg_sw_mroute_cnt++;
			else
				sg_sw_mroute_cnt++;
		} else {
			if (pim_addr_is_any(*oil_origin(c_oil)))
				starg_hw_mroute_cnt++;
			else
				sg_hw_mroute_cnt++;
		}
	}

	for (ALL_LIST_ELEMENTS_RO(pim->static_routes, node, s_route)) {
		if (!s_route->c_oil.installed) {
			if (pim_addr_is_any(*oil_origin(&s_route->c_oil)))
				starg_sw_mroute_cnt++;
			else
				sg_sw_mroute_cnt++;
		} else {
			if (pim_addr_is_any(*oil_origin(&s_route->c_oil)))
				starg_hw_mroute_cnt++;
			else
				sg_hw_mroute_cnt++;
		}
	}

	if (!json) {
		vty_out(vty, "%-20s %u/%u\n", "(*, G)", starg_hw_mroute_cnt,
			starg_sw_mroute_cnt + starg_hw_mroute_cnt);
		vty_out(vty, "%-20s %u/%u\n", "(S, G)", sg_hw_mroute_cnt,
			sg_sw_mroute_cnt + sg_hw_mroute_cnt);
		vty_out(vty, "------\n");
		vty_out(vty, "%-20s %u/%u\n", "Total",
			(starg_hw_mroute_cnt + sg_hw_mroute_cnt),
			(starg_sw_mroute_cnt + starg_hw_mroute_cnt +
			 sg_sw_mroute_cnt + sg_hw_mroute_cnt));
	} else {
		/* (*,G) route details */
		json_starg = json_object_new_object();
		json_object_object_add(json, "wildcardGroup", json_starg);

		json_object_int_add(json_starg, "installed",
				    starg_hw_mroute_cnt);
		json_object_int_add(json_starg, "total",
				    starg_sw_mroute_cnt + starg_hw_mroute_cnt);

		/* (S, G) route details */
		json_sg = json_object_new_object();
		json_object_object_add(json, "sourceGroup", json_sg);

		json_object_int_add(json_sg, "installed", sg_hw_mroute_cnt);
		json_object_int_add(json_sg, "total",
				    sg_sw_mroute_cnt + sg_hw_mroute_cnt);

		json_object_int_add(json, "totalNumOfInstalledMroutes",
				    starg_hw_mroute_cnt + sg_hw_mroute_cnt);
		json_object_int_add(json, "totalNumOfMroutes",
				    starg_sw_mroute_cnt + starg_hw_mroute_cnt +
					    sg_sw_mroute_cnt +
					    sg_hw_mroute_cnt);
	}
}

int clear_ip_mroute_count_command(struct vty *vty, const char *name)
{
	struct listnode *node;
	struct channel_oil *c_oil;
	struct static_route *sr;
	struct vrf *v = pim_cmd_lookup(vty, name);
	struct pim_instance *pim;

	if (!v)
		return CMD_WARNING;

	pim = v->info;
	frr_each (rb_pim_oil, &pim->channel_oil_head, c_oil) {
		if (!c_oil->installed)
			continue;

		pim_mroute_update_counters(c_oil);
		c_oil->cc.origpktcnt = c_oil->cc.pktcnt;
		c_oil->cc.origbytecnt = c_oil->cc.bytecnt;
		c_oil->cc.origwrong_if = c_oil->cc.wrong_if;
	}

	for (ALL_LIST_ELEMENTS_RO(pim->static_routes, node, sr)) {
		if (!sr->c_oil.installed)
			continue;

		pim_mroute_update_counters(&sr->c_oil);

		sr->c_oil.cc.origpktcnt = sr->c_oil.cc.pktcnt;
		sr->c_oil.cc.origbytecnt = sr->c_oil.cc.bytecnt;
		sr->c_oil.cc.origwrong_if = sr->c_oil.cc.wrong_if;
	}
	return CMD_SUCCESS;
}

struct vrf *pim_cmd_lookup(struct vty *vty, const char *name)
{
	struct vrf *vrf;

	if (name)
		vrf = vrf_lookup_by_name(name);
	else
		vrf = vrf_lookup_by_id(VRF_DEFAULT);

	if (!vrf)
		vty_out(vty, "Specified VRF: %s does not exist\n", name);

	return vrf;
}

void clear_mroute(struct pim_instance *pim)
{
	struct pim_upstream *up;
	struct interface *ifp;

	/* scan interfaces */
	FOR_ALL_INTERFACES (pim->vrf, ifp) {
		struct pim_interface *pim_ifp = ifp->info;
		struct pim_ifchannel *ch;

		if (!pim_ifp)
			continue;

		/* deleting all ifchannels */
		while (!RB_EMPTY(pim_ifchannel_rb, &pim_ifp->ifchannel_rb)) {
			ch = RB_ROOT(pim_ifchannel_rb, &pim_ifp->ifchannel_rb);

			pim_ifchannel_delete(ch);
		}

#if PIM_IPV == 4
		/* clean up all igmp groups */
		struct gm_group *grp;

		if (pim_ifp->gm_group_list) {
			while (pim_ifp->gm_group_list->count) {
				grp = listnode_head(pim_ifp->gm_group_list);
				igmp_group_delete(grp);
			}
		}
#else
		struct gm_if *gm_ifp;

		gm_ifp = pim_ifp->mld;
		if (gm_ifp)
			gm_group_delete(gm_ifp);
#endif
	}

	/* clean up all upstreams*/
	while ((up = rb_pim_upstream_first(&pim->upstream_head)))
		pim_upstream_del(pim, up, __func__);
}

void clear_pim_statistics(struct pim_instance *pim)
{
	struct interface *ifp;

	pim->bsm_rcvd = 0;
	pim->bsm_sent = 0;
	pim->bsm_dropped = 0;

	/* scan interfaces */
	FOR_ALL_INTERFACES (pim->vrf, ifp) {
		struct pim_interface *pim_ifp = ifp->info;

		if (!pim_ifp)
			continue;

		pim_ifp->pim_ifstat_bsm_cfg_miss = 0;
		pim_ifp->pim_ifstat_ucast_bsm_cfg_miss = 0;
		pim_ifp->pim_ifstat_bsm_invalid_sz = 0;
	}
}

int clear_pim_interface_traffic(const char *vrf, struct vty *vty)
{
	struct interface *ifp = NULL;
	struct pim_interface *pim_ifp = NULL;

	struct vrf *v = pim_cmd_lookup(vty, vrf);

	if (!v)
		return CMD_WARNING;

	FOR_ALL_INTERFACES (v, ifp) {
		pim_ifp = ifp->info;

		if (!pim_ifp)
			continue;

		pim_ifp->pim_ifstat_hello_recv = 0;
		pim_ifp->pim_ifstat_hello_sent = 0;
		pim_ifp->pim_ifstat_join_recv = 0;
		pim_ifp->pim_ifstat_join_send = 0;
		pim_ifp->pim_ifstat_prune_recv = 0;
		pim_ifp->pim_ifstat_prune_send = 0;
		pim_ifp->pim_ifstat_reg_recv = 0;
		pim_ifp->pim_ifstat_reg_send = 0;
		pim_ifp->pim_ifstat_reg_stop_recv = 0;
		pim_ifp->pim_ifstat_reg_stop_send = 0;
		pim_ifp->pim_ifstat_assert_recv = 0;
		pim_ifp->pim_ifstat_assert_send = 0;
		pim_ifp->pim_ifstat_bsm_rx = 0;
		pim_ifp->pim_ifstat_bsm_tx = 0;
#if PIM_IPV == 4
		pim_ifp->igmp_ifstat_joins_sent = 0;
		pim_ifp->igmp_ifstat_joins_failed = 0;
		pim_ifp->igmp_peak_group_count = 0;
#endif
	}

	return CMD_SUCCESS;
}

int pim_debug_pim_cmd(void)
{
	PIM_DO_DEBUG_PIM_EVENTS;
	PIM_DO_DEBUG_PIM_PACKETS;
	PIM_DO_DEBUG_PIM_TRACE;
	PIM_DO_DEBUG_MSDP_EVENTS;
	PIM_DO_DEBUG_MSDP_PACKETS;
	PIM_DO_DEBUG_BSM;
	PIM_DO_DEBUG_VXLAN;
	return CMD_SUCCESS;
}

int pim_no_debug_pim_cmd(void)
{
	PIM_DONT_DEBUG_PIM_EVENTS;
	PIM_DONT_DEBUG_PIM_PACKETS;
	PIM_DONT_DEBUG_PIM_TRACE;
	PIM_DONT_DEBUG_MSDP_EVENTS;
	PIM_DONT_DEBUG_MSDP_PACKETS;

	PIM_DONT_DEBUG_PIM_PACKETDUMP_SEND;
	PIM_DONT_DEBUG_PIM_PACKETDUMP_RECV;
	PIM_DONT_DEBUG_BSM;
	PIM_DONT_DEBUG_VXLAN;
	return CMD_SUCCESS;
}

int pim_debug_pim_packets_cmd(const char *hello, const char *joins,
			      const char *registers, struct vty *vty)
{
	if (hello) {
		PIM_DO_DEBUG_PIM_HELLO;
		vty_out(vty, "PIM Hello debugging is on\n");
	} else if (joins) {
		PIM_DO_DEBUG_PIM_J_P;
		vty_out(vty, "PIM Join/Prune debugging is on\n");
	} else if (registers) {
		PIM_DO_DEBUG_PIM_REG;
		vty_out(vty, "PIM Register debugging is on\n");
	} else {
		PIM_DO_DEBUG_PIM_PACKETS;
		vty_out(vty, "PIM Packet debugging is on\n");
	}
	return CMD_SUCCESS;
}

int pim_no_debug_pim_packets_cmd(const char *hello, const char *joins,
				 const char *registers, struct vty *vty)
{
	if (hello) {
		PIM_DONT_DEBUG_PIM_HELLO;
		vty_out(vty, "PIM Hello debugging is off\n");
	} else if (joins) {
		PIM_DONT_DEBUG_PIM_J_P;
		vty_out(vty, "PIM Join/Prune debugging is off\n");
	} else if (registers) {
		PIM_DONT_DEBUG_PIM_REG;
		vty_out(vty, "PIM Register debugging is off\n");
	} else {
		PIM_DONT_DEBUG_PIM_PACKETS;
		vty_out(vty, "PIM Packet debugging is off\n");
	}

	return CMD_SUCCESS;
}

int pim_show_rpf_helper(const char *vrf, struct vty *vty, bool json)
{
	struct pim_instance *pim;
	struct vrf *v;
	json_object *json_parent = NULL;

	v = vrf_lookup_by_name(vrf ? vrf : VRF_DEFAULT_NAME);

	if (!v)
		return CMD_WARNING;

	pim = v->info;

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

int pim_show_rpf_vrf_all_helper(struct vty *vty, bool json)
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

int pim_show_rp_helper(const char *vrf, struct vty *vty, const char *group_str,
		       const struct prefix *group, bool json)
{
	struct pim_instance *pim;
	struct vrf *v;
	json_object *json_parent = NULL;
	struct prefix *range = NULL;

	v = vrf_lookup_by_name(vrf ? vrf : VRF_DEFAULT_NAME);

	if (!v)
		return CMD_WARNING;

	pim = v->info;

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

int pim_show_rp_vrf_all_helper(struct vty *vty, const char *group_str,
			       const struct prefix *group, bool json)
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

int pim_show_secondary_helper(const char *vrf, struct vty *vty)
{
	struct pim_instance *pim;
	struct vrf *v;

	v = vrf_lookup_by_name(vrf ? vrf : VRF_DEFAULT_NAME);

	if (!v)
		return CMD_WARNING;

	pim = v->info;

	if (!pim) {
		vty_out(vty, "%% Unable to find pim instance\n");
		return CMD_WARNING;
	}

	pim_show_neighbors_secondary(pim, vty);

	return CMD_SUCCESS;
}

int pim_show_statistics_helper(const char *vrf, struct vty *vty,
			       const char *word, bool uj)
{
	struct pim_instance *pim;
	struct vrf *v;

	v = vrf_lookup_by_name(vrf ? vrf : VRF_DEFAULT_NAME);

	if (!v)
		return CMD_WARNING;

	pim = v->info;

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

int pim_show_upstream_helper(const char *vrf, struct vty *vty, pim_addr s_or_g,
			     pim_addr g, bool json)
{
	pim_sgaddr sg = {0};
	struct vrf *v;
	struct pim_instance *pim;
	json_object *json_parent = NULL;

	v = vrf_lookup_by_name(vrf ? vrf : VRF_DEFAULT_NAME);

	if (!v) {
		vty_out(vty, "%% Vrf specified: %s does not exist\n", vrf);
		return CMD_WARNING;
	}
	pim = v->info;

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

	pim_show_upstream(pim, vty, &sg, json_parent);

	if (json)
		vty_json(vty, json_parent);

	return CMD_SUCCESS;
}

int pim_show_upstream_vrf_all_helper(struct vty *vty, bool json)
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

int pim_show_upstream_join_desired_helper(const char *vrf, struct vty *vty,
					  bool uj)
{
	struct pim_instance *pim;
	struct vrf *v;

	v = vrf_lookup_by_name(vrf ? vrf : VRF_DEFAULT_NAME);

	if (!v)
		return CMD_WARNING;

	pim = v->info;

	if (!pim) {
		vty_out(vty, "%% Unable to find pim instance\n");
		return CMD_WARNING;
	}

	pim_show_join_desired(pim, vty, uj);

	return CMD_SUCCESS;
}

int pim_show_upstream_rpf_helper(const char *vrf, struct vty *vty, bool uj)
{
	struct pim_instance *pim;
	struct vrf *v;

	v = vrf_lookup_by_name(vrf ? vrf : VRF_DEFAULT_NAME);

	if (!v)
		return CMD_WARNING;

	pim = v->info;

	if (!pim) {
		vty_out(vty, "%% Unable to find pim instance\n");
		return CMD_WARNING;
	}

	pim_show_upstream_rpf(pim, vty, uj);

	return CMD_SUCCESS;
}

int pim_show_state_helper(const char *vrf, struct vty *vty,
			  const char *s_or_g_str, const char *g_str, bool json)
{
	struct pim_instance *pim;
	struct vrf *v;
	json_object *json_parent = NULL;

	v = vrf_lookup_by_name(vrf ? vrf : VRF_DEFAULT_NAME);

	if (!v)
		return CMD_WARNING;

	pim = v->info;

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

int pim_show_state_vrf_all_helper(struct vty *vty, const char *s_or_g_str,
				  const char *g_str, bool json)
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

int pim_show_multicast_helper(const char *vrf, struct vty *vty)
{
	struct vrf *v;
	struct pim_instance *pim;

	v = vrf_lookup_by_name(vrf ? vrf : VRF_DEFAULT_NAME);

	if (!v)
		return CMD_WARNING;

	pim = v->info;

	if (!pim) {
		vty_out(vty, "%% Unable to find pim instance\n");
		return CMD_WARNING;
	}

	pim_cmd_show_ip_multicast_helper(pim, vty);

	return CMD_SUCCESS;
}

int pim_show_multicast_vrf_all_helper(struct vty *vty)
{
	struct vrf *vrf;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		vty_out(vty, "VRF: %s\n", vrf->name);
		pim_cmd_show_ip_multicast_helper(vrf->info, vty);
	}

	return CMD_SUCCESS;
}

int pim_show_multicast_count_helper(const char *vrf, struct vty *vty, bool json)
{
	struct pim_instance *pim;
	struct vrf *v;
	json_object *json_parent = NULL;

	v = vrf_lookup_by_name(vrf ? vrf : VRF_DEFAULT_NAME);

	if (!v)
		return CMD_WARNING;

	pim = v->info;

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

int pim_show_multicast_count_vrf_all_helper(struct vty *vty, bool json)
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

int pim_show_mroute_helper(const char *vrf, struct vty *vty, pim_addr s_or_g,
			   pim_addr g, bool fill, bool json)
{
	pim_sgaddr sg = {0};
	struct pim_instance *pim;
	struct vrf *v;
	json_object *json_parent = NULL;

	v = vrf_lookup_by_name(vrf ? vrf : VRF_DEFAULT_NAME);

	if (!v)
		return CMD_WARNING;

	pim = v->info;

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

	show_mroute(pim, vty, &sg, fill, json_parent);

	if (json)
		vty_json(vty, json_parent);

	return CMD_SUCCESS;
}

int pim_show_mroute_vrf_all_helper(struct vty *vty, bool fill, bool json)
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
		show_mroute(vrf->info, vty, &sg, fill, json_vrf);
		if (json)
			json_object_object_add(json_parent, vrf->name,
					       json_vrf);
	}
	if (json)
		vty_json(vty, json_parent);

	return CMD_SUCCESS;
}

int pim_show_mroute_count_helper(const char *vrf, struct vty *vty, bool json)
{
	struct pim_instance *pim;
	struct vrf *v;
	json_object *json_parent = NULL;

	v = vrf_lookup_by_name(vrf ? vrf : VRF_DEFAULT_NAME);

	if (!v)
		return CMD_WARNING;

	pim = v->info;

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

int pim_show_mroute_count_vrf_all_helper(struct vty *vty, bool json)
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

int pim_show_mroute_summary_helper(const char *vrf, struct vty *vty, bool json)
{
	struct pim_instance *pim;
	struct vrf *v;
	json_object *json_parent = NULL;

	v = vrf_lookup_by_name(vrf ? vrf : VRF_DEFAULT_NAME);

	if (!v)
		return CMD_WARNING;

	pim = v->info;

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

int pim_show_mroute_summary_vrf_all_helper(struct vty *vty, bool json)
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

void pim_show_interface_traffic(struct pim_instance *pim, struct vty *vty,
				bool uj)
{
	struct interface *ifp = NULL;
	struct pim_interface *pim_ifp = NULL;
	json_object *json = NULL;
	json_object *json_row = NULL;

	if (uj)
		json = json_object_new_object();
	else {
		vty_out(vty, "\n");
		vty_out(vty, "%-16s%-17s%-17s%-17s%-17s%-17s%-17s%-17s\n",
			"Interface", "       HELLO", "       JOIN",
			"      PRUNE", "   REGISTER", "REGISTER-STOP",
			"  ASSERT", "  BSM");
		vty_out(vty, "%-16s%-17s%-17s%-17s%-17s%-17s%-17s%-17s\n", "",
			"       Rx/Tx", "       Rx/Tx", "      Rx/Tx",
			"      Rx/Tx", "     Rx/Tx", "    Rx/Tx", "   Rx/Tx");
		vty_out(vty,
			"---------------------------------------------------------------------------------------------------------------\n");
	}

	FOR_ALL_INTERFACES (pim->vrf, ifp) {
		pim_ifp = ifp->info;

		if (!pim_ifp)
			continue;

		if (uj) {
			json_row = json_object_new_object();
			json_object_pim_ifp_add(json_row, ifp);
			json_object_int_add(json_row, "helloRx",
					    pim_ifp->pim_ifstat_hello_recv);
			json_object_int_add(json_row, "helloTx",
					    pim_ifp->pim_ifstat_hello_sent);
			json_object_int_add(json_row, "joinRx",
					    pim_ifp->pim_ifstat_join_recv);
			json_object_int_add(json_row, "joinTx",
					    pim_ifp->pim_ifstat_join_send);
			json_object_int_add(json_row, "pruneRx",
					    pim_ifp->pim_ifstat_prune_recv);
			json_object_int_add(json_row, "pruneTx",
					    pim_ifp->pim_ifstat_prune_send);
			json_object_int_add(json_row, "registerRx",
					    pim_ifp->pim_ifstat_reg_recv);
			json_object_int_add(json_row, "registerTx",
					    pim_ifp->pim_ifstat_reg_send);
			json_object_int_add(json_row, "registerStopRx",
					    pim_ifp->pim_ifstat_reg_stop_recv);
			json_object_int_add(json_row, "registerStopTx",
					    pim_ifp->pim_ifstat_reg_stop_send);
			json_object_int_add(json_row, "assertRx",
					    pim_ifp->pim_ifstat_assert_recv);
			json_object_int_add(json_row, "assertTx",
					    pim_ifp->pim_ifstat_assert_send);
			json_object_int_add(json_row, "bsmRx",
					    pim_ifp->pim_ifstat_bsm_rx);
			json_object_int_add(json_row, "bsmTx",
					    pim_ifp->pim_ifstat_bsm_tx);
			json_object_object_add(json, ifp->name, json_row);
		} else {
			vty_out(vty,
				"%-16s %8u/%-8u %7u/%-7u %7u/%-7u %7u/%-7u %7u/%-7u %7u/%-7u %7" PRIu64
				"/%-7" PRIu64 "\n",
				ifp->name, pim_ifp->pim_ifstat_hello_recv,
				pim_ifp->pim_ifstat_hello_sent,
				pim_ifp->pim_ifstat_join_recv,
				pim_ifp->pim_ifstat_join_send,
				pim_ifp->pim_ifstat_prune_recv,
				pim_ifp->pim_ifstat_prune_send,
				pim_ifp->pim_ifstat_reg_recv,
				pim_ifp->pim_ifstat_reg_send,
				pim_ifp->pim_ifstat_reg_stop_recv,
				pim_ifp->pim_ifstat_reg_stop_send,
				pim_ifp->pim_ifstat_assert_recv,
				pim_ifp->pim_ifstat_assert_send,
				pim_ifp->pim_ifstat_bsm_rx,
				pim_ifp->pim_ifstat_bsm_tx);
		}
	}
	if (uj)
		vty_json(vty, json);
}

void pim_show_interface_traffic_single(struct pim_instance *pim,
				       struct vty *vty, const char *ifname,
				       bool uj)
{
	struct interface *ifp = NULL;
	struct pim_interface *pim_ifp = NULL;
	json_object *json = NULL;
	json_object *json_row = NULL;
	uint8_t found_ifname = 0;

	if (uj)
		json = json_object_new_object();
	else {
		vty_out(vty, "\n");
		vty_out(vty, "%-16s%-17s%-17s%-17s%-17s%-17s%-17s%-17s\n",
			"Interface", "    HELLO", "    JOIN", "   PRUNE",
			"   REGISTER", "  REGISTER-STOP", "  ASSERT",
			"    BSM");
		vty_out(vty, "%-14s%-18s%-17s%-17s%-17s%-17s%-17s%-17s\n", "",
			"      Rx/Tx", "     Rx/Tx", "    Rx/Tx", "    Rx/Tx",
			"     Rx/Tx", "    Rx/Tx", "    Rx/Tx");
		vty_out(vty,
			"-------------------------------------------------------------------------------------------------------------------------------\n");
	}

	FOR_ALL_INTERFACES (pim->vrf, ifp) {
		if (strcmp(ifname, ifp->name))
			continue;

		pim_ifp = ifp->info;

		if (!pim_ifp)
			continue;

		found_ifname = 1;
		if (uj) {
			json_row = json_object_new_object();
			json_object_pim_ifp_add(json_row, ifp);
			json_object_int_add(json_row, "helloRx",
					    pim_ifp->pim_ifstat_hello_recv);
			json_object_int_add(json_row, "helloTx",
					    pim_ifp->pim_ifstat_hello_sent);
			json_object_int_add(json_row, "joinRx",
					    pim_ifp->pim_ifstat_join_recv);
			json_object_int_add(json_row, "joinTx",
					    pim_ifp->pim_ifstat_join_send);
			json_object_int_add(json_row, "pruneRx",
					    pim_ifp->pim_ifstat_prune_recv);
			json_object_int_add(json_row, "pruneTx",
					    pim_ifp->pim_ifstat_prune_send);
			json_object_int_add(json_row, "registerRx",
					    pim_ifp->pim_ifstat_reg_recv);
			json_object_int_add(json_row, "registerTx",
					    pim_ifp->pim_ifstat_reg_send);
			json_object_int_add(json_row, "registerStopRx",
					    pim_ifp->pim_ifstat_reg_stop_recv);
			json_object_int_add(json_row, "registerStopTx",
					    pim_ifp->pim_ifstat_reg_stop_send);
			json_object_int_add(json_row, "assertRx",
					    pim_ifp->pim_ifstat_assert_recv);
			json_object_int_add(json_row, "assertTx",
					    pim_ifp->pim_ifstat_assert_send);
			json_object_int_add(json_row, "bsmRx",
					    pim_ifp->pim_ifstat_bsm_rx);
			json_object_int_add(json_row, "bsmTx",
					    pim_ifp->pim_ifstat_bsm_tx);

			json_object_object_add(json, ifp->name, json_row);
		} else {
			vty_out(vty,
				"%-16s %8u/%-8u %7u/%-7u %7u/%-7u %7u/%-7u %7u/%-7u %7u/%-7u %7" PRIu64
				"/%-7" PRIu64 "\n",
				ifp->name, pim_ifp->pim_ifstat_hello_recv,
				pim_ifp->pim_ifstat_hello_sent,
				pim_ifp->pim_ifstat_join_recv,
				pim_ifp->pim_ifstat_join_send,
				pim_ifp->pim_ifstat_prune_recv,
				pim_ifp->pim_ifstat_prune_send,
				pim_ifp->pim_ifstat_reg_recv,
				pim_ifp->pim_ifstat_reg_send,
				pim_ifp->pim_ifstat_reg_stop_recv,
				pim_ifp->pim_ifstat_reg_stop_send,
				pim_ifp->pim_ifstat_assert_recv,
				pim_ifp->pim_ifstat_assert_send,
				pim_ifp->pim_ifstat_bsm_rx,
				pim_ifp->pim_ifstat_bsm_tx);
		}
	}
	if (uj)
		vty_json(vty, json);
	else if (!found_ifname)
		vty_out(vty, "%% No such interface\n");
}

int pim_show_interface_traffic_helper(const char *vrf, const char *if_name,
				      struct vty *vty, bool uj)
{
	struct pim_instance *pim;
	struct vrf *v;

	v = vrf_lookup_by_name(vrf ? vrf : VRF_DEFAULT_NAME);

	if (!v)
		return CMD_WARNING;

	pim = v->info;

	if (!pim) {
		vty_out(vty, "%% Unable to find pim instance\n");
		return CMD_WARNING;
	}

	if (if_name)
		pim_show_interface_traffic_single(v->info, vty, if_name, uj);
	else
		pim_show_interface_traffic(v->info, vty, uj);

	return CMD_SUCCESS;
}

void clear_pim_interfaces(struct pim_instance *pim)
{
	struct interface *ifp;

	FOR_ALL_INTERFACES (pim->vrf, ifp) {
		if (ifp->info)
			pim_neighbor_delete_all(ifp, "interface cleared");
	}
}

void pim_show_bsr(struct pim_instance *pim, struct vty *vty, bool uj)
{
	char uptime[10];
	char last_bsm_seen[10];
	time_t now;
	char bsr_state[20];
	json_object *json = NULL;

	if (pim_addr_is_any(pim->global_scope.current_bsr)) {
		pim_time_uptime(uptime, sizeof(uptime),
				pim->global_scope.current_bsr_first_ts);
		pim_time_uptime(last_bsm_seen, sizeof(last_bsm_seen),
				pim->global_scope.current_bsr_last_ts);
	}

	else {
		now = pim_time_monotonic_sec();
		pim_time_uptime(uptime, sizeof(uptime),
				(now - pim->global_scope.current_bsr_first_ts));
		pim_time_uptime(last_bsm_seen, sizeof(last_bsm_seen),
				now - pim->global_scope.current_bsr_last_ts);
	}

	switch (pim->global_scope.state) {
	case NO_INFO:
		strlcpy(bsr_state, "NO_INFO", sizeof(bsr_state));
		break;
	case ACCEPT_ANY:
		strlcpy(bsr_state, "ACCEPT_ANY", sizeof(bsr_state));
		break;
	case ACCEPT_PREFERRED:
		strlcpy(bsr_state, "ACCEPT_PREFERRED", sizeof(bsr_state));
		break;
	default:
		strlcpy(bsr_state, "", sizeof(bsr_state));
	}


	if (uj) {
		json = json_object_new_object();
		json_object_string_addf(json, "bsr", "%pPA",
					&pim->global_scope.current_bsr);
		json_object_int_add(json, "priority",
				    pim->global_scope.current_bsr_prio);
		json_object_int_add(json, "fragmentTag",
				    pim->global_scope.bsm_frag_tag);
		json_object_string_add(json, "state", bsr_state);
		json_object_string_add(json, "upTime", uptime);
		json_object_string_add(json, "lastBsmSeen", last_bsm_seen);
	}

	else {
		vty_out(vty, "PIMv2 Bootstrap information\n");
		vty_out(vty, "Current preferred BSR address: %pPA\n",
			&pim->global_scope.current_bsr);
		vty_out(vty,
			"Priority        Fragment-Tag       State           UpTime\n");
		vty_out(vty, "  %-12d    %-12d    %-13s    %7s\n",
			pim->global_scope.current_bsr_prio,
			pim->global_scope.bsm_frag_tag, bsr_state, uptime);
		vty_out(vty, "Last BSM seen: %s\n", last_bsm_seen);
	}

	if (uj)
		vty_json(vty, json);
}

int pim_show_bsr_helper(const char *vrf, struct vty *vty, bool uj)
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

	pim_show_bsr(v->info, vty, uj);

	return CMD_SUCCESS;
}

/*Display the group-rp mappings */
static void pim_show_group_rp_mappings_info(struct pim_instance *pim,
					    struct vty *vty, bool uj)
{
	struct bsgrp_node *bsgrp;
	struct bsm_rpinfo *bsm_rp;
	struct route_node *rn;
	json_object *json = NULL;
	json_object *json_group = NULL;
	json_object *json_row = NULL;
	struct ttable *tt = NULL;

	if (uj) {
		json = json_object_new_object();
		json_object_string_addf(json, "BSR Address", "%pPA",
					&pim->global_scope.current_bsr);
	} else
		vty_out(vty, "BSR Address  %pPA\n",
			&pim->global_scope.current_bsr);

	for (rn = route_top(pim->global_scope.bsrp_table); rn;
	     rn = route_next(rn)) {
		bsgrp = (struct bsgrp_node *)rn->info;

		if (!bsgrp)
			continue;

		char grp_str[PREFIX_STRLEN];

		prefix2str(&bsgrp->group, grp_str, sizeof(grp_str));

		if (uj) {
			json_object_object_get_ex(json, grp_str, &json_group);
			if (!json_group) {
				json_group = json_object_new_object();
				json_object_object_add(json, grp_str,
						       json_group);
			}
		} else {
			vty_out(vty, "Group Address %pFX\n", &bsgrp->group);
			vty_out(vty, "--------------------------\n");
			/* Prepare table. */
			tt = ttable_new(&ttable_styles[TTSTYLE_BLANK]);
			ttable_add_row(tt, "Rp Address|priority|Holdtime|Hash");
			tt->style.cell.rpad = 2;
			tt->style.corner = '+';
			ttable_restyle(tt);

			ttable_add_row(tt, "%s|%c|%c|%c", "(ACTIVE)", ' ', ' ',
				       ' ');
		}

		frr_each (bsm_rpinfos, bsgrp->bsrp_list, bsm_rp) {
			if (uj) {
				json_row = json_object_new_object();
				json_object_string_addf(json_row, "Rp Address",
							"%pPA",
							&bsm_rp->rp_address);
				json_object_int_add(json_row, "Rp HoldTime",
						    bsm_rp->rp_holdtime);
				json_object_int_add(json_row, "Rp Priority",
						    bsm_rp->rp_prio);
				json_object_int_add(json_row, "Hash Val",
						    bsm_rp->hash);
				json_object_object_addf(json_group, json_row,
							"%pPA",
							&bsm_rp->rp_address);

			} else {
				ttable_add_row(
					tt, "%pPA|%u|%u|%u",
					&bsm_rp->rp_address, bsm_rp->rp_prio,
					bsm_rp->rp_holdtime, bsm_rp->hash);
			}
		}
		/* Dump the generated table. */
		if (tt) {
			char *table = NULL;

			table = ttable_dump(tt, "\n");
			vty_out(vty, "%s\n", table);
			XFREE(MTYPE_TMP, table);
			ttable_del(tt);
			tt = NULL;
		}
		if (!bsm_rpinfos_count(bsgrp->bsrp_list) && !uj)
			vty_out(vty, "Active List is empty.\n");

		if (uj) {
			json_object_int_add(json_group, "Pending RP count",
					    bsgrp->pend_rp_cnt);
		} else {
			vty_out(vty, "(PENDING)\n");
			vty_out(vty, "Pending RP count :%d\n",
				bsgrp->pend_rp_cnt);
			if (bsgrp->pend_rp_cnt) {
				/* Prepare table. */
				tt = ttable_new(&ttable_styles[TTSTYLE_BLANK]);
				ttable_add_row(
					tt,
					"Rp Address|priority|Holdtime|Hash");
				tt->style.cell.rpad = 2;
				tt->style.corner = '+';
				ttable_restyle(tt);
			}
		}

		frr_each (bsm_rpinfos, bsgrp->partial_bsrp_list, bsm_rp) {
			if (uj) {
				json_row = json_object_new_object();
				json_object_string_addf(json_row, "Rp Address",
							"%pPA",
							&bsm_rp->rp_address);
				json_object_int_add(json_row, "Rp HoldTime",
						    bsm_rp->rp_holdtime);
				json_object_int_add(json_row, "Rp Priority",
						    bsm_rp->rp_prio);
				json_object_int_add(json_row, "Hash Val",
						    bsm_rp->hash);
				json_object_object_addf(json_group, json_row,
							"%pPA",
							&bsm_rp->rp_address);
			} else {
				ttable_add_row(
					tt, "%pPA|%u|%u|%u",
					&bsm_rp->rp_address, bsm_rp->rp_prio,
					bsm_rp->rp_holdtime, bsm_rp->hash);
			}
		}
		/* Dump the generated table. */
		if (tt) {
			char *table = NULL;

			table = ttable_dump(tt, "\n");
			vty_out(vty, "%s\n", table);
			XFREE(MTYPE_TMP, table);
			ttable_del(tt);
		}
		if (!bsm_rpinfos_count(bsgrp->partial_bsrp_list) && !uj)
			vty_out(vty, "Partial List is empty\n");

		if (!uj)
			vty_out(vty, "\n");
	}

	if (uj)
		vty_json(vty, json);
}

int pim_show_group_rp_mappings_info_helper(const char *vrf, struct vty *vty,
					   bool uj)
{
	struct pim_instance *pim;
	struct vrf *v;

	v = vrf_lookup_by_name(vrf ? vrf : VRF_DEFAULT_NAME);

	if (!v)
		return CMD_WARNING;

	pim = v->info;

	if (!pim) {
		vty_out(vty, "%% Unable to find pim instance\n");
		return CMD_WARNING;
	}

	pim_show_group_rp_mappings_info(v->info, vty, uj);

	return CMD_SUCCESS;
}

/* Display the bsm database details */
static void pim_show_bsm_db(struct pim_instance *pim, struct vty *vty, bool uj)
{
	int count = 0;
	int fragment = 1;
	struct bsm_frag *bsfrag;
	json_object *json = NULL;
	json_object *json_group = NULL;
	json_object *json_row = NULL;

	count = bsm_frags_count(pim->global_scope.bsm_frags);

	if (uj) {
		json = json_object_new_object();
		json_object_int_add(json, "Number of the fragments", count);
	} else {
		vty_out(vty, "Scope Zone: Global\n");
		vty_out(vty, "Number of the fragments: %d\n", count);
		vty_out(vty, "\n");
	}

	frr_each (bsm_frags, pim->global_scope.bsm_frags, bsfrag) {
		char grp_str[PREFIX_STRLEN];
		struct bsmmsg_grpinfo *group;
		struct bsmmsg_rpinfo *bsm_rpinfo;
		struct prefix grp;
		struct bsm_hdr *hdr;
		pim_addr bsr_addr;
		uint32_t offset = 0;
		uint8_t *buf;
		uint32_t len = 0;
		uint32_t frag_rp_cnt = 0;

		buf = bsfrag->data;
		len = bsfrag->size;

		/* skip pim header */
		buf += PIM_MSG_HEADER_LEN;
		len -= PIM_MSG_HEADER_LEN;

		hdr = (struct bsm_hdr *)buf;
		/* NB: bshdr->bsr_addr.addr is packed/unaligned => memcpy */
		memcpy(&bsr_addr, &hdr->bsr_addr.addr, sizeof(bsr_addr));

		/* BSM starts with bsr header */
		buf += sizeof(struct bsm_hdr);
		len -= sizeof(struct bsm_hdr);

		if (uj) {
			json_object_string_addf(json, "BSR address", "%pPA",
						&bsr_addr);
			json_object_int_add(json, "BSR priority",
					    hdr->bsr_prio);
			json_object_int_add(json, "Hashmask Length",
					    hdr->hm_len);
			json_object_int_add(json, "Fragment Tag",
					    ntohs(hdr->frag_tag));
		} else {
			vty_out(vty, "BSM Fragment : %d\n", fragment);
			vty_out(vty, "------------------\n");
			vty_out(vty, "%-15s %-15s %-15s %-15s\n", "BSR-Address",
				"BSR-Priority", "Hashmask-len", "Fragment-Tag");
			vty_out(vty, "%-15pPA %-15d %-15d %-15d\n", &bsr_addr,
				hdr->bsr_prio, hdr->hm_len,
				ntohs(hdr->frag_tag));
		}

		vty_out(vty, "\n");

		while (offset < len) {
			group = (struct bsmmsg_grpinfo *)buf;

			if (group->group.family == PIM_MSG_ADDRESS_FAMILY_IPV4)
				grp.family = AF_INET;
			else if (group->group.family ==
				 PIM_MSG_ADDRESS_FAMILY_IPV6)
				grp.family = AF_INET6;

			grp.prefixlen = group->group.mask;
#if PIM_IPV == 4
			grp.u.prefix4 = group->group.addr;
#else
			grp.u.prefix6 = group->group.addr;
#endif

			prefix2str(&grp, grp_str, sizeof(grp_str));

			buf += sizeof(struct bsmmsg_grpinfo);
			offset += sizeof(struct bsmmsg_grpinfo);

			if (uj) {
				json_object_object_get_ex(json, grp_str,
							  &json_group);
				if (!json_group) {
					json_group = json_object_new_object();
					json_object_int_add(json_group,
							    "Rp Count",
							    group->rp_count);
					json_object_int_add(
						json_group, "Fragment Rp count",
						group->frag_rp_count);
					json_object_object_add(json, grp_str,
							       json_group);
				}
			} else {
				vty_out(vty, "Group : %s\n", grp_str);
				vty_out(vty, "-------------------\n");
				vty_out(vty, "Rp Count:%d\n", group->rp_count);
				vty_out(vty, "Fragment Rp Count : %d\n",
					group->frag_rp_count);
			}

			frag_rp_cnt = group->frag_rp_count;

			if (!frag_rp_cnt)
				continue;

			if (!uj)
				vty_out(vty,
					"RpAddress     HoldTime     Priority\n");

			while (frag_rp_cnt--) {
				pim_addr rp_addr;

				bsm_rpinfo = (struct bsmmsg_rpinfo *)buf;
				/* unaligned, again */
				memcpy(&rp_addr, &bsm_rpinfo->rpaddr.addr,
				       sizeof(rp_addr));

				buf += sizeof(struct bsmmsg_rpinfo);
				offset += sizeof(struct bsmmsg_rpinfo);

				if (uj) {
					json_row = json_object_new_object();
					json_object_string_addf(
						json_row, "Rp Address", "%pPA",
						&rp_addr);
					json_object_int_add(
						json_row, "Rp HoldTime",
						ntohs(bsm_rpinfo->rp_holdtime));
					json_object_int_add(json_row,
							    "Rp Priority",
							    bsm_rpinfo->rp_pri);
					json_object_object_addf(
						json_group, json_row, "%pPA",
						&rp_addr);
				} else {
					vty_out(vty, "%-15pPA %-12d %d\n",
						&rp_addr,
						ntohs(bsm_rpinfo->rp_holdtime),
						bsm_rpinfo->rp_pri);
				}
			}
			vty_out(vty, "\n");
		}

		fragment++;
	}

	if (uj)
		vty_json(vty, json);
}

int pim_show_bsm_db_helper(const char *vrf, struct vty *vty, bool uj)
{
	struct pim_instance *pim;
	struct vrf *v;

	v = vrf_lookup_by_name(vrf ? vrf : VRF_DEFAULT_NAME);

	if (!v)
		return CMD_WARNING;

	pim = v->info;

	if (!pim) {
		vty_out(vty, "%% Unable to find pim instance\n");
		return CMD_WARNING;
	}

	pim_show_bsm_db(v->info, vty, uj);

	return CMD_SUCCESS;
}
