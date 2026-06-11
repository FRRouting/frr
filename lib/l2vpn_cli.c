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

#include "lib/l2vpn_svc.h"

#include "lib/l2vpn_cli_clippy.c"

static void show_l2vpn_vpws(struct vty *vty, const char *name, bool detail, bool json);
static void show_l2vpn_vpls(struct vty *vty, const char *name, bool detail, bool json);

DEFPY_YANG_NOSH(l2vpn_command,
	l2vpn_cmd,
	"l2vpn WORD$l2vpn_name type <vpls|vpws>$l2vpn_type",
	"Configure l2vpn commands\n"
	"L2VPN name\n"
	"L2VPN type\n"
	"Virtual Private LAN Service\n"
	"Virtual Private Wire Service\n")
{
	char xpath[XPATH_MAXLEN];
	int rv;

	snprintf(xpath, sizeof(xpath), "/frr-l2vpn:l2vpn/l2vpn-instance[name='%s'][type='%s']",
		 l2vpn_name, l2vpn_type);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	rv = nb_cli_apply_changes(vty, NULL);
	if (rv == CMD_SUCCESS)
		VTY_PUSH_XPATH(L2VPN_NODE, xpath);

	return rv;
}

DEFPY_YANG(
	no_l2vpn_command,
	no_l2vpn_cmd,
	"no l2vpn WORD$l2vpn_name type <vpls|vpws>$l2vpn_type",
	NO_STR
	"Configure l2vpn commands\n"
	"L2VPN name\n"
	"L2VPN type\n"
	"Virtual Private LAN Service\n"
	"Virtual Private Wire Service\n")
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), "/frr-l2vpn:l2vpn/l2vpn-instance[name='%s'][type='%s']",
		 l2vpn_name, l2vpn_type);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	l2vpn_bridge,
	l2vpn_bridge_cmd,
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

DEFPY_YANG(
	l2vpn_mtu,
	l2vpn_mtu_cmd,
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

DEFPY_YANG(
	l2vpn_vc_type,
	l2vpn_vc_type_cmd,
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

DEFPY_YANG(
	l2vpn_member_interface,
	l2vpn_member_interface_cmd,
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

DEFPY_YANG_NOSH(
	l2vpn_member_pseudowire,
	l2vpn_member_pseudowire_cmd,
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
		VTY_PUSH_XPATH(L2VPN_PSEUDOWIRE_NODE, xpath_index);

	return rv;
}

DEFPY_YANG(
	no_l2vpn_member_pseudowire,
	no_l2vpn_member_pseudowire_cmd,
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

DEFPY_YANG(
	l2vpn_control_word,
	l2vpn_control_word_cmd,
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

DEFPY_YANG(
	l2vpn_neighbor_address,
	l2vpn_neighbor_address_cmd,
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

DEFPY_YANG(
	l2vpn_neighbor_lsr_id,
	l2vpn_neighbor_lsr_id_cmd,
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

DEFPY_YANG(
	l2vpn_pw_id,
	l2vpn_pw_id_cmd,
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

DEFPY_YANG(
	l2vpn_evpn_ignore_mtu_mismatch,
	l2vpn_evpn_ignore_mtu_mismatch_cmd,
	"[no] ignore-mtu-mismatch disable",
	NO_STR
	"Configure ignore remote mtu mismatch\n"
	"Disable ignore remote mtu mismatch\n")
{
	nb_cli_enqueue_change(vty, "./ignore-mtu-mismatch", NB_OP_MODIFY, no ? "true" : "false");

	return nb_cli_apply_changes(vty, NULL);

}

DEFPY_YANG(
	l2vpn_pw_status_disable,
	l2vpn_pw_status_disable_cmd,
	"[no] pw-status disable",
	NO_STR
	"Configure PW status\n"
	"Disable PW status\n")
{
	nb_cli_enqueue_change(vty, "./pw-status", NB_OP_MODIFY, no ? "true" : "false");

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(show_l2vpn, show_l2vpn_cmd,
      "show l2vpn NAME$name [vpws|vpls]$type [detail $detail] [json $json]",
      SHOW_STR "L2VPN\n"
      "L2VPN name\n"
      "Type virtual private wired service\n"
      "Type virtual private LAN service\n"
      "Detail\n"
      "Json output\n")
{
	if (!type) {
		show_l2vpn_vpls(vty, name, !!detail, !!json);
		show_l2vpn_vpws(vty, name, !!detail, !!json);
	} else if (!strcmp("vpws", type)) {
		show_l2vpn_vpws(vty, name, !!detail, !!json);
	} else {
		show_l2vpn_vpls(vty, name, !!detail, !!json);
	}

	return CMD_SUCCESS;
}

DEFPY_YANG_NOSH(
	l2vpn_member_evpn,
	l2vpn_member_evpn_cmd,
	"member evpn IFNAME$ifname",
	"L2VPN evpn member configuration\n"
	"EVPN interface\n"
	"Interface's name\n")
{
	char xpath_index[XPATH_MAXLEN + 32 + IFNAMSIZ];
	int rv;

	snprintf(xpath_index, sizeof(xpath_index), "%s/member-evpn[interface='%s']",
		 VTY_CURR_XPATH, ifname);

	nb_cli_enqueue_change(vty, xpath_index, NB_OP_CREATE, NULL);

	rv = nb_cli_apply_changes(vty, NULL);
	if (rv == CMD_SUCCESS)
		VTY_PUSH_XPATH(L2VPN_EVPN_NODE, xpath_index);

	return rv;
}

DEFPY_YANG(
	no_l2vpn_member_evpn,
	no_l2vpn_member_evpn_cmd,
	"no member evpn IFNAME$ifname",
	NO_STR
	"L2VPN evpn member configuration\n"
	"EVPN interface\n"
	"Interface's name\n")
{
	char xpath_index[XPATH_MAXLEN + 32 + IFNAMSIZ];

	snprintf(xpath_index, sizeof(xpath_index), "%s/member-evpn[interface='%s']",
		 VTY_CURR_XPATH, ifname);

	nb_cli_enqueue_change(vty, xpath_index, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	l2vpn_evpn_vni,
	l2vpn_evpn_vni_cmd,
	"[no] vni (1-16777215)$vni",
	NO_STR
	"When EVPN over vxlan, specify BGP EVPN vni used for this VPWS\n"
	"BGP EVPN vni value\n")
{
	if (no)
		nb_cli_enqueue_change(vty, "./vni", NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, "./vni", NB_OP_MODIFY, vni_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	l2vpn_evpn_neighbor,
	l2vpn_evpn_neighbor_cmd,
	"[no] neighbor evpn local-vsi (1-16777215)$vsi remote-vsi (1-16777215)$rvsi",
	NO_STR
	"Remote endpoint configuration\n"
	"Specify that L2VPN uses information from BGP EVPN\n"
	"Define local VPWS instance identifier\n"
	"Local VPWS instance identifier value\n"
	"Define remote VPWS instance identifier\n"
	"Remote VPWS instance identifier value\n")
{
	char xpath[XPATH_MAXLEN], xpath_val[XPATH_MAXLEN + 32];
	enum nb_operation operation = NB_OP_MODIFY;

	snprintf(xpath, sizeof(xpath), "./neighbor-evpn");
	if (no)
		operation = NB_OP_DESTROY;

	nb_cli_enqueue_change(vty, xpath, operation, NULL);
	snprintf(xpath_val, sizeof(xpath_val), "%s/local-vsi", xpath);
	nb_cli_enqueue_change(vty, xpath_val, operation, vsi_str);

	snprintf(xpath_val, sizeof(xpath_val), "%s/remote-vsi", xpath);
	nb_cli_enqueue_change(vty, xpath_val, operation, rvsi_str);

	return nb_cli_apply_changes(vty, NULL);
}

struct cmd_node l2vpn_node = {
	.name = "l2vpn",
	.node = L2VPN_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(config-l2vpn)# ",
};

struct cmd_node l2vpn_pseudowire_node = {
	.name = "pseudowire",
	.node = L2VPN_PSEUDOWIRE_NODE,
	.parent_node = L2VPN_NODE,
	.prompt = "%s(config-l2vpn-pw)# ",
};

struct cmd_node l2vpn_evpn_node = {
	.name = "evpn",
	.node = L2VPN_EVPN_NODE,
	.parent_node = L2VPN_NODE,
	.prompt = "%s(config-l2vpn-evpn)# ",
};

static void l2vpn_autocomplete(vector comps, struct cmd_token *token)
{
	struct l2vpn *l2vpn;

	RB_FOREACH (l2vpn, l2vpn_head, &l2vpn_tree_config)
		vector_set(comps, XSTRDUP(MTYPE_COMPLETION, l2vpn->name));
}

static const struct cmd_variable_handler l2vpn_var_handlers[] = {
	{ .varname = "l2vpn_name", .completions = l2vpn_autocomplete },
	{ .completions = NULL }
};

void l2vpn_cli_init(void)
{
	cmd_variable_handler_register(l2vpn_var_handlers);
	install_node(&l2vpn_node);
	install_node(&l2vpn_pseudowire_node);
	install_node(&l2vpn_evpn_node);
	install_default(L2VPN_NODE);
	install_default(L2VPN_PSEUDOWIRE_NODE);
	install_default(L2VPN_EVPN_NODE);
	install_element(ENABLE_NODE, &show_l2vpn_cmd);
	install_element(CONFIG_NODE, &l2vpn_cmd);
	install_element(CONFIG_NODE, &no_l2vpn_cmd);

	install_element(L2VPN_NODE, &l2vpn_mtu_cmd);
	install_element(L2VPN_NODE, &l2vpn_bridge_cmd);
	install_element(L2VPN_NODE, &l2vpn_vc_type_cmd);
	install_element(L2VPN_NODE, &l2vpn_member_pseudowire_cmd);
	install_element(L2VPN_NODE, &no_l2vpn_member_pseudowire_cmd);
	install_element(L2VPN_NODE, &l2vpn_member_evpn_cmd);
	install_element(L2VPN_NODE, &no_l2vpn_member_evpn_cmd);
	install_element(L2VPN_NODE, &l2vpn_member_interface_cmd);

	install_element(L2VPN_PSEUDOWIRE_NODE, &l2vpn_pw_status_disable_cmd);
	install_element(L2VPN_PSEUDOWIRE_NODE, &l2vpn_control_word_cmd);
	install_element(L2VPN_PSEUDOWIRE_NODE, &l2vpn_neighbor_address_cmd);
	install_element(L2VPN_PSEUDOWIRE_NODE, &l2vpn_neighbor_lsr_id_cmd);
	install_element(L2VPN_PSEUDOWIRE_NODE, &l2vpn_pw_id_cmd);

	install_element(L2VPN_EVPN_NODE, &l2vpn_evpn_neighbor_cmd);
	install_element(L2VPN_EVPN_NODE, &l2vpn_evpn_vni_cmd);
	install_element(L2VPN_EVPN_NODE, &l2vpn_evpn_ignore_mtu_mismatch_cmd);
}

static void l2vpn_instance_show(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const char *name = yang_dnode_get_string(dnode, "./name");
	const char *pwtype = NULL, *type;
	const char *bridge_name = NULL;
	uint16_t mtu;

	type = yang_dnode_get_string(dnode, "./type");
	vty_out(vty, "l2vpn %s type %s\n", name, type);

	if (yang_dnode_exists(dnode, "./pw-type")) {
		pwtype = yang_dnode_get_string(dnode, "./pw-type");
		if (!strcmp(pwtype, "ethernet-tagged"))
			vty_out(vty, " vc type %s\n", pwtype);
	}

	if (yang_dnode_exists(dnode, "./mtu")) {
		mtu = yang_dnode_get_uint16(dnode, "./mtu");
		if (mtu != DEFAULT_L2VPN_MTU)
			vty_out(vty, " mtu %d\n", mtu);
	}

	if (yang_dnode_exists(dnode, "./bridge-interface")) {
		bridge_name = yang_dnode_get_string(dnode, "./bridge-interface");
		if (bridge_name)
			vty_out(vty, " bridge %s\n", bridge_name);
	}
}

static void l2vpn_instance_show_end(struct vty *vty, const struct lyd_node *dnode)
{
	vty_out(vty, "exit\n");
	vty_out(vty, "!\n");
}

static void l2vpn_instance_member_pseudowire_show(struct vty *vty, const struct lyd_node *dnode,
						  bool show_defaults)

{
	const char *name = yang_dnode_get_string(dnode, "./interface");
	uint32_t pw_id;
	struct ipaddr lsr_id;
	struct ipaddr address;

	vty_out(vty, " member pseudowire %s\n", name);

	if (!yang_dnode_get_bool(dnode, "./pw-status"))
		vty_out(vty, "  pw-status disable\n");

	if (yang_dnode_exists(dnode, "./pw-id")) {
		pw_id = yang_dnode_get_uint32(dnode, "./pw-id");
		if (pw_id != 0)
			vty_out(vty, "  pw-id %u\n", pw_id);
		else
			vty_out(vty, "  ! Incomplete config, specify a pw-id\n");
	}

	if (yang_dnode_exists(dnode, "./neighbor-lsr-id")) {
		yang_dnode_get_ip(&lsr_id, dnode, "./neighbor-lsr-id");
		if (lsr_id.ipaddr_v4.s_addr != INADDR_ANY)
			vty_out(vty, "  neighbor lsr-id %pI4\n", &lsr_id.ipaddr_v4);
		else
			vty_out(vty, "  ! Incomplete config, specify a neighbor lsr-id\n");
	}

	if (yang_dnode_exists(dnode, "./neighbor-address")) {
		yang_dnode_get_ip(&address, dnode, "./neighbor-address");
		if (address.ipa_type == IPADDR_V4)
			vty_out(vty, "  neighbor address %pI4\n", &address.ipaddr_v4);
		else if (address.ipa_type == IPADDR_V6)
			vty_out(vty, "  neighbor address %pI6\n", &address.ipaddr_v6);
	}

	if (!yang_dnode_get_bool(dnode, "./control-word"))
		vty_out(vty, "  control-word exclude\n");
}

static void l2vpn_instance_member_pseudowire_show_end(struct vty *vty, const struct lyd_node *dnode)
{
	vty_out(vty, " exit\n");
	vty_out(vty, " !\n");
}

static void l2vpn_instance_member_interface_show(struct vty *vty, const struct lyd_node *dnode,
						 bool show_defaults)
{
	const char *name = yang_dnode_get_string(dnode, "./interface");

	vty_out(vty, " member interface %s\n", name);
}

static void l2vpn_instance_member_evpn_show(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults)
{
	uint32_t vni, vsi;
	const char *name = yang_dnode_get_string(dnode, "./interface");

	vty_out(vty, " member evpn %s\n", name);

	if (yang_dnode_exists(dnode, "./vni")) {
		vni = yang_dnode_get_uint32(dnode, "./vni");
		vty_out(vty, "  vni %u\n", vni);
	}

	if (!yang_dnode_exists(dnode, "./neighbor-evpn/local-vsi"))
		return;

	vsi = yang_dnode_get_uint32(dnode, "./neighbor-evpn/local-vsi");
	vty_out(vty, "  neighbor evpn local-vsi %u ", vsi);
	if (yang_dnode_exists(dnode, "./neighbor-evpn/remote-vsi")) {
		vsi = yang_dnode_get_uint32(dnode, "./neighbor-evpn/remote-vsi");
		vty_out(vty, "remote-vsi %u\n", vsi);
	} else {
		vty_out(vty, "\n");
	}

	if (!yang_dnode_get_bool(dnode, "./ignore-mtu-mismatch"))
		vty_out(vty, "  ignore-mtu-mismatch disable\n");
}

static void show_l2vpn_vpls(struct vty *vty, const char *name, bool detail, bool json)
{
	struct l2vpn *l2vpn;

	l2vpn = l2vpn_find(&l2vpn_tree_config, name, L2VPN_TYPE_VPLS);
	if (!l2vpn)
		return;

	/* TODO */
}

static void show_l2vpn_vpws(struct vty *vty, const char *name, bool detail, bool json)
{
	bool state;
	struct l2vpn *l2vpn;
	struct interface *ifp;
	struct l2vpn_svc *l2vpn_svc;
	char buf[81] = { 0 }, buf_esi[ESI_STR_LEN] = { 0 };

	l2vpn = l2vpn_find(&l2vpn_tree_config, name, L2VPN_TYPE_VPWS);
	if (!l2vpn)
		return;

	if (json) {
		json_object *list = json_object_new_array(), *json_neighs, *json_neigh;
		json_object *json = json_object_new_object(), *json_elt, *json_list_item;

		json_object_string_add(json, "name", name);
		json_object_string_add(json, "type", "Virtual Private Wire Service");
		if (!detail) {
			RB_FOREACH (l2vpn_svc, l2vpn_svc_head, &l2vpn->svc_tree) {
				json_elt = json_object_new_object();
				json_object_string_add(json_elt, "memberEVPN", l2vpn_svc->ifname);
				json_object_string_add(json_elt, "role", "Primary");
				json_object_string_add(json_elt, "esi",
						       esi_to_str(&l2vpn_svc->esi, buf_esi,
								  sizeof(buf_esi)));
				json_object_int_add(json_elt, "localVsi", l2vpn_svc->vsi);
				json_object_int_add(json_elt, "remoteVsi", l2vpn_svc->remote_vsi);
				state = l2vpn_svc->local_status == EVPN_FORWARDING &&
					l2vpn_svc->remote_status == EVPN_FORWARDING;
				json_object_string_add(json_elt, "state", state ? "Up" : "Down");
				json_object_string_add(json_elt, "protocol", "BGP");
				json_object_array_add(list, json_elt);
			}

			json_object_object_add(json, "instances", list);
			vty_json(vty, json);

			return;
		}

		RB_FOREACH (l2vpn_svc, l2vpn_svc_head, &l2vpn->svc_tree) {
			json_neighs = json_object_new_array();
			json_elt = json_object_new_object();
			json_list_item = json_object_new_object();

			json_object_string_add(json_elt, "memberEVPN", l2vpn_svc->ifname);
			json_object_int_add(json_elt, "vsi", l2vpn_svc->vsi);
			json_object_string_add(json_elt, "interface",
					       l2vpn_svc->local_ac[0] ? l2vpn_svc->local_ac
								      : "<undefined>");
			ifp = if_lookup_by_name_all_vrf(l2vpn_svc->local_ac);
			json_object_string_add(json_elt, "state",
					       ifp && if_is_operative(ifp) ? "Up" : "Down");
			json_object_string_add(json_elt, "status",
					       evpn_status_to_str(l2vpn_svc->local_status));
			json_object_string_add(json_elt, "esi",
					       esi_to_str(&l2vpn_svc->esi, buf_esi,
							  sizeof(buf_esi)));
			json_object_string_add(json_elt, "mode", "single-homed");
			json_object_string_add(json_elt, "role", "Primary");
			json_object_string_add(json_elt, "protocol", "BGP");
			json_object_object_add(json_list_item, "local", json_elt);

			json_elt = json_object_new_object();
			json_object_int_add(json_elt, "vsi", l2vpn_svc->remote_vsi);

			/* Currently only one neighbor that is in single-homed mode */
			json_neigh = json_object_new_object();
			json_object_string_addf(json_neigh, "addr", "%pI4", &l2vpn_svc->lsr_id);
			state = l2vpn_svc->remote_status == EVPN_FORWARDING;
			json_object_string_add(json_neigh, "state", state ? "Up" : "Down");
			json_object_string_add(json_neigh, "status",
					       l2vpn_svc_error_code(l2vpn_svc->reason));
			json_object_int_add(json_neigh, "mtu", l2vpn_svc->remote_mtu);
			json_object_string_add(json_neigh, "encap", "VXLAN");
			json_object_int_add(json_neigh, "vni", l2vpn_svc->vni);
			json_object_boolean_add(json_neigh, "ignoreMtuMismatch",
						l2vpn_svc->ignore_mtu_mismatch);
			json_object_string_addf(json_neigh, "nexthop", "%pI4",
						&l2vpn_svc->addr.ipv4);
			json_object_array_add(json_neighs, json_neigh);

			json_object_object_add(json_elt, "neighbors", json_neighs);
			json_object_object_add(json_list_item, "remote", json_elt);
			json_object_array_add(list, json_list_item);
		}

		json_object_object_add(json, "instances", list);
		vty_json(vty, json);
	} else {
		vty_out(vty, "Virtual Private Wire Service\n");

		if (!detail) {
			vty_out(vty, "%-19s %-19s %-29s %-9s %-9s %-9s\n", "EVPN",
				"Local/Remote VSI", "ESI ", "State", "Role", "PROTO");
			memset(buf, '-', 19);
			memset(buf_esi, '-', ESI_STR_LEN - 1);
			vty_out(vty, "%s %s %s ", buf, buf, buf_esi);
			buf[9] = '\0';
			vty_out(vty, "%s %s %s\n", buf, buf, buf);
			RB_FOREACH (l2vpn_svc, l2vpn_svc_head, &l2vpn->svc_tree) {
				vty_out(vty, "%-19s ", l2vpn_svc->ifname);
				snprintf(buf, sizeof(buf), "%u/%u", l2vpn_svc->vsi,
					 l2vpn_svc->remote_vsi);
				vty_out(vty, "%-19s ", buf);
				vty_out(vty, "%-29s ",
					esi_to_str(&l2vpn_svc->esi, buf_esi, sizeof(buf_esi)));
				state = l2vpn_svc->local_status == EVPN_FORWARDING &&
					l2vpn_svc->remote_status == EVPN_FORWARDING;
				vty_out(vty, "%-9s ", state ? "Up" : "Down");
				vty_out(vty, "%-9s ", "Primary");
				vty_out(vty, "%-9s\n", "BGP");
				vty_out(vty, "\n");
			}

			return;
		}

		RB_FOREACH (l2vpn_svc, l2vpn_svc_head, &l2vpn->svc_tree) {
			vty_out(vty, "EVPN %s\n", l2vpn_svc->ifname);
			state = l2vpn_svc->local_status != EVPN_LOCAL_TX_FAULT;
			ifp = if_lookup_by_name_all_vrf(l2vpn_svc->local_ac);
			vty_out(vty, " AC: %s, state is %s\n",
				l2vpn_svc->local_ac[0] ? l2vpn_svc->local_ac : "<undefined>",
				ifp && if_is_operative(ifp) ? "Up" : "Down");
			vty_out(vty, "     VSI %u\n", l2vpn_svc->vsi);
			vty_out(vty, "     ESI: %s\n",
				esi_to_str(&l2vpn_svc->esi, buf_esi, sizeof(buf_esi)));
			vty_out(vty, "     Status: %s (%d)\n",
				evpn_status_to_str(l2vpn_svc->local_status),
				l2vpn_svc->local_status);
			vty_out(vty, "     Mode: single-homed\n");
			vty_out(vty, "     Role: Primary\n");

			state = l2vpn_svc->remote_status == EVPN_FORWARDING;
			vty_out(vty, " Remote VSI %u:\n", l2vpn_svc->remote_vsi);
			/* Currently only one neighbor that is in single-homed mode */
			vty_out(vty, "  neighbor %pI4, state is %s:\n", &l2vpn_svc->lsr_id,
				state ? "Up" : "Down");
			vty_out(vty, "   Status: %s\n", l2vpn_svc_error_code(l2vpn_svc->reason));
			vty_out(vty, "   MTU: %u\n", l2vpn_svc->remote_mtu);
			vty_out(vty, "   Encapsulation VXLAN, VNI %u\n", l2vpn_svc->vni);
			vty_out(vty, "   Ignore MTU mismatch: %s\n",
				l2vpn_svc->ignore_mtu_mismatch ? "true" : "false");
			vty_out(vty, "   Nexthop: %pI4\n", &l2vpn_svc->addr.ipv4);
			vty_out(vty, "\n");
		}
	}
}

const struct frr_yang_module_info frr_l2vpn_cli_info = {
	.name = "frr-l2vpn",
	.ignore_cfg_cbs = true,
	.nodes = {
		{
			.xpath = "/frr-l2vpn:l2vpn/l2vpn-instance",
			.cbs = {
				.cli_show = l2vpn_instance_show,
				.cli_show_end = l2vpn_instance_show_end,
			}
		},
		{
			.xpath = "/frr-l2vpn:l2vpn/l2vpn-instance/member-interface",
			.cbs = {
				.cli_show = l2vpn_instance_member_interface_show,
			}
		},
		{
			.xpath = "/frr-l2vpn:l2vpn/l2vpn-instance/member-pseudowire",
			.cbs = {
				.cli_show = l2vpn_instance_member_pseudowire_show,
				.cli_show_end = l2vpn_instance_member_pseudowire_show_end,
			}
		},
		{
			.xpath = "/frr-l2vpn:l2vpn/l2vpn-instance/member-evpn",
			.cbs.cli_show = l2vpn_instance_member_evpn_show,
		},
		{
			.xpath = NULL,
		},
	}
};
