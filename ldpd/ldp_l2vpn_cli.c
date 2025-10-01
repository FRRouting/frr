// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * LDP L2VPNnorthbound CLI implementation.
 *
 * Copyright (C) 2019 Network Device Education Foundation, Inc. ("NetDEF")
 *                    Rafael Zalamena
 */

#include <zebra.h>

#include "lib/command.h"
#include "lib/northbound_cli.h"

#include "ldp_l2vpn.h"

#include "ldpd/ldpd.h"
#include "ldpd/ldp_vty.h"

#ifndef VTYSH_EXTRACT_PL
#include "ldpd/ldp_l2vpn_cli_clippy.c"
#endif /* VTYSH_EXTRACT_PL */


DEFPY_YANG_NOSH(ldp_l2vpn,
	ldp_l2vpn_cmd,
	"l2vpn WORD$l2vpn_name type vpls",
	"Configure l2vpn commands\n"
	"L2VPN name\n"
	"L2VPN type\n"
	"Virtual Private LAN Service\n")
{
	char xpath[XPATH_MAXLEN];
	int rv;

	snprintf(xpath, sizeof(xpath),
		 "/frr-ldp-l2vpn:l2vpn/l2vpn-instance[name='%s'][type='vpls']", l2vpn_name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	rv = nb_cli_apply_changes(vty, NULL);
	if (rv == CMD_SUCCESS)
		VTY_PUSH_XPATH(LDP_L2VPN_NODE, xpath);

	return rv;
}

DEFPY_YANG (no_ldp_l2vpn,
	no_ldp_l2vpn_cmd,
	"no l2vpn WORD$l2vpn_name type vpls",
	NO_STR
	"Configure l2vpn commands\n"
	"L2VPN name\n"
	"L2VPN type\n"
	"Virtual Private LAN Service\n")
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath),
		 "/frr-ldp-l2vpn:l2vpn/l2vpn-instance[name='%s'][type='vpls']", l2vpn_name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG  (ldp_l2vpn_bridge,
	ldp_l2vpn_bridge_cmd,
	"[no] bridge IFNAME$ifname",
	NO_STR
	"Bridge interface\n"
	"Interface's name\n")
{
	if (no)
		nb_cli_enqueue_change(vty, "./bridge-interface", NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, "./bridge-interface", NB_OP_MODIFY, ifname);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG  (ldp_l2vpn_mtu,
	ldp_l2vpn_mtu_cmd,
	"[no] mtu (1500-9180)$mtu",
	NO_STR
	"Set Maximum Transmission Unit\n"
	"Maximum Transmission Unit value\n")
{
	if (no)
		nb_cli_enqueue_change(vty, "./mtu", NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, "./mtu", NB_OP_MODIFY, mtu_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG  (ldp_l2vpn_vc_type,
	ldp_l2vpn_vc_type_cmd,
	"[no] vc type <ethernet|ethernet-tagged>$vc_type",
	NO_STR
	"Virtual Circuit options\n"
	"Virtual Circuit type to use\n"
	"Ethernet (type 5)\n"
	"Ethernet-tagged (type 4)\n")
{
	if (no)
		nb_cli_enqueue_change(vty, "./pw-type", NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, "./pw-type", NB_OP_MODIFY, vc_type);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG  (ldp_l2vpn_member_interface,
	ldp_l2vpn_member_interface_cmd,
	"[no] member interface IFNAME$ifname",
	NO_STR
	"L2VPN member configuration\n"
	"Local interface\n"
	"Interface's name\n")
{
	char xpath_index[XPATH_MAXLEN + 32 + IFNAMSIZ];

	snprintf(xpath_index, sizeof(xpath_index), "./member-interface[interface='%s']", ifname);
	if (no)
		nb_cli_enqueue_change(vty, xpath_index, NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, xpath_index, NB_OP_CREATE, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG_NOSH(ldp_l2vpn_member_pseudowire,
	ldp_l2vpn_member_pseudowire_cmd,
	"member pseudowire IFNAME$ifname",
	"L2VPN member configuration\n"
	"Pseudowire interface\n"
	"Interface's name\n")
{
	char xpath_index[XPATH_MAXLEN + 32 + IFNAMSIZ];
	int rv;

	snprintf(xpath_index, sizeof(xpath_index), "%s/member-pseudowire[interface='%s']",
		 VTY_CURR_XPATH, ifname);
	nb_cli_enqueue_change(vty, xpath_index, NB_OP_CREATE, NULL);

	rv = nb_cli_apply_changes(vty, NULL);
	if (rv == CMD_SUCCESS)
		VTY_PUSH_XPATH(LDP_PSEUDOWIRE_NODE, xpath_index);

	return rv;
}

DEFPY_YANG  (no_ldp_l2vpn_member_pseudowire,
	no_ldp_l2vpn_member_pseudowire_cmd,
	"no member pseudowire IFNAME$ifname",
	NO_STR
	"L2VPN member configuration\n"
	"Pseudowire interface\n"
	"Interface's name\n")
{
	char xpath_index[XPATH_MAXLEN + 32 + IFNAMSIZ];

	snprintf(xpath_index, sizeof(xpath_index), "%s/member-pseudowire[interface='%s']",
		 VTY_CURR_XPATH, ifname);

	nb_cli_enqueue_change(vty, xpath_index, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG  (ldp_l2vpn_control_word,
	ldp_l2vpn_control_word_cmd,
	"[no] control-word <exclude$exclude|include$include>",
	NO_STR
	"Control-word options\n"
	"Exclude control-word in pseudowire packets\n"
	"Include control-word in pseudowire packets\n")
{
	bool control_word = false;

	if ((no && exclude) || (!no && include))
		control_word = true;

	nb_cli_enqueue_change(vty, "./control-word", NB_OP_MODIFY, control_word ? "true" : "false");

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG  (ldp_l2vpn_neighbor_address,
	ldp_l2vpn_neighbor_address_cmd,
	"[no] neighbor address <A.B.C.D|X:X::X:X>$pw_address",
	NO_STR
	"Remote endpoint configuration\n"
	"Specify the IPv4 or IPv6 address of the remote endpoint\n"
	"IPv4 address\n"
	"IPv6 address\n")
{
	if (no)
		nb_cli_enqueue_change(vty, "./neighbor-address", NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, "./neighbor-address", NB_OP_MODIFY, pw_address_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG  (ldp_l2vpn_neighbor_lsr_id,
	ldp_l2vpn_neighbor_lsr_id_cmd,
	"[no] neighbor lsr-id A.B.C.D$address",
	NO_STR
	"Remote endpoint configuration\n"
	"Specify the LSR-ID of the remote endpoint\n"
	"IPv4 address\n")
{
	if (no)
		nb_cli_enqueue_change(vty, "./neighbor-lsr-id", NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, "./neighbor-lsr-id", NB_OP_MODIFY, address_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG  (ldp_l2vpn_pw_id,
	ldp_l2vpn_pw_id_cmd,
	"[no] pw-id (1-4294967295)$pwid",
	NO_STR
	"Set the Virtual Circuit ID\n"
	"Virtual Circuit ID value\n")
{
	if (no)
		nb_cli_enqueue_change(vty, "./pw-id", NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, "./pw-id", NB_OP_MODIFY, pwid_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG  (ldp_l2vpn_pw_status_disable,
	ldp_l2vpn_pw_status_disable_cmd,
	"[no] pw-status disable",
	NO_STR
	"Configure PW status\n"
	"Disable PW status\n")
{
	nb_cli_enqueue_change(vty, "./pw-status", NB_OP_MODIFY, no ? "true" : "false");

	return nb_cli_apply_changes(vty, NULL);
}

static void ldp_l2vpn_pw_config_write(struct vty *vty, struct l2vpn_pw *pw)
{
	int missing_lsrid = 0;
	int missing_pwid = 0;

	vty_out(vty, " !\n");
	vty_out(vty, " member pseudowire %s\n", pw->ifname);

	if (pw->lsr_id.s_addr != INADDR_ANY)
		vty_out(vty, "  neighbor lsr-id %pI4\n", &pw->lsr_id);
	else
		missing_lsrid = 1;

	if (pw->flags & F_PW_STATIC_NBR_ADDR)
		vty_out(vty, "  neighbor address %s\n", log_addr(pw->af, &pw->addr));

	if (pw->pwid != 0)
		vty_out(vty, "  pw-id %u\n", pw->pwid);
	else
		missing_pwid = 1;

	if (!(pw->flags & F_PW_CWORD_CONF))
		vty_out(vty, "  control-word exclude\n");

	if (!(pw->flags & F_PW_STATUSTLV_CONF))
		vty_out(vty, "  pw-status disable\n");

	if (missing_lsrid)
		vty_out(vty, "  ! Incomplete config, specify a neighbor lsr-id\n");
	if (missing_pwid)
		vty_out(vty, "  ! Incomplete config, specify a pw-id\n");

	vty_out(vty, " exit\n");
}

static int ldp_l2vpn_config_write(struct vty *vty)
{
	struct l2vpn *l2vpn;
	struct l2vpn_if *lif;
	struct l2vpn_pw *pw;

	RB_FOREACH (l2vpn, l2vpn_head, &ldpd_conf->l2vpn_tree) {
		vty_out(vty, "l2vpn %s type vpls\n", l2vpn->name);

		if (l2vpn->pw_type != DEFAULT_PW_TYPE)
			vty_out(vty, " vc type ethernet-tagged\n");

		if (l2vpn->mtu != DEFAULT_L2VPN_MTU)
			vty_out(vty, " mtu %u\n", l2vpn->mtu);

		if (l2vpn->br_ifname[0] != '\0')
			vty_out(vty, " bridge %s\n", l2vpn->br_ifname);

		RB_FOREACH (lif, l2vpn_if_head, &l2vpn->if_tree)
			vty_out(vty, " member interface %s\n", lif->ifname);

		RB_FOREACH (pw, l2vpn_pw_head, &l2vpn->pw_tree)
			ldp_l2vpn_pw_config_write(vty, pw);
		RB_FOREACH (pw, l2vpn_pw_head, &l2vpn->pw_inactive_tree)
			ldp_l2vpn_pw_config_write(vty, pw);

		vty_out(vty, " !\n");
		vty_out(vty, "exit\n");
		vty_out(vty, "!\n");
	}

	return (0);
}

struct cmd_node ldp_l2vpn_node = {
	.name = "ldp l2vpn",
	.node = LDP_L2VPN_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(config-l2vpn)# ",
	.config_write = ldp_l2vpn_config_write,
};

struct cmd_node ldp_pseudowire_node = {
	.name = "ldp",
	.node = LDP_PSEUDOWIRE_NODE,
	.parent_node = LDP_L2VPN_NODE,
	.prompt = "%s(config-l2vpn-pw)# ",
};

void ldp_l2vpn_cli_init(void)
{
	install_node(&ldp_l2vpn_node);
	install_node(&ldp_pseudowire_node);
	install_default(LDP_L2VPN_NODE);
	install_default(LDP_PSEUDOWIRE_NODE);
	install_element(CONFIG_NODE, &ldp_l2vpn_cmd);
	install_element(CONFIG_NODE, &no_ldp_l2vpn_cmd);

	install_element(LDP_L2VPN_NODE, &ldp_l2vpn_bridge_cmd);
	install_element(LDP_L2VPN_NODE, &ldp_l2vpn_mtu_cmd);
	install_element(LDP_L2VPN_NODE, &ldp_l2vpn_vc_type_cmd);

	install_element(LDP_L2VPN_NODE, &ldp_l2vpn_member_interface_cmd);
	install_element(LDP_L2VPN_NODE, &ldp_l2vpn_member_pseudowire_cmd);
	install_element(LDP_L2VPN_NODE, &no_ldp_l2vpn_member_pseudowire_cmd);

	install_element(LDP_PSEUDOWIRE_NODE, &ldp_l2vpn_control_word_cmd);
	install_element(LDP_PSEUDOWIRE_NODE, &ldp_l2vpn_neighbor_address_cmd);
	install_element(LDP_PSEUDOWIRE_NODE, &ldp_l2vpn_neighbor_lsr_id_cmd);
	install_element(LDP_PSEUDOWIRE_NODE, &ldp_l2vpn_pw_id_cmd);
	install_element(LDP_PSEUDOWIRE_NODE, &ldp_l2vpn_pw_status_disable_cmd);
}
