// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * LDP L2VPNnorthbound CLI implementation.
 *
 * Copyright (C) 2019 Network Device Education Foundation, Inc. ("NetDEF")
 *                    Rafael Zalamena
 */

#include <zebra.h>

#include "lib/memory.h"
#include "lib/command.h"
#include "lib/northbound_cli.h"

#include "lib/l2vpn.h"

#include "lib/l2vpn_cli_clippy.c"

struct l2vpn_lib_register l2vpn_lib_master = { NULL, NULL, NULL, NULL };
struct l2vpn_head l2vpn_tree_config;

/* clang-format off */

static inline int     l2vpn_compare(const struct l2vpn *, const struct l2vpn *);
static inline int     l2vpn_if_compare(const struct l2vpn_if *, const struct l2vpn_if *);
static inline int     l2vpn_pw_compare(const struct l2vpn_pw *, const struct l2vpn_pw *);

/* clang-format on */

DEFINE_QOBJ_TYPE(l2vpn_if);
DEFINE_QOBJ_TYPE(l2vpn_pw);
DEFINE_QOBJ_TYPE(l2vpn);

DEFINE_MTYPE_STATIC(LIB, L2VPN, "L2VPN entry");
DEFINE_MTYPE_STATIC(LIB, L2VPN_PWE, "L2VPN PWE entry");
DEFINE_MTYPE_STATIC(LIB, L2VPN_IF, "L2VPN IF entry");

RB_GENERATE(l2vpn_head, l2vpn, entry, l2vpn_compare)
RB_GENERATE(l2vpn_if_head, l2vpn_if, entry, l2vpn_if_compare)
RB_GENERATE(l2vpn_pw_head, l2vpn_pw, entry, l2vpn_pw_compare)

/* clang-format off */

static inline int
l2vpn_compare(const struct l2vpn *a, const struct l2vpn *b)
{
	return strcmp(a->name, b->name);
}

static inline int l2vpn_pw_compare(const struct l2vpn_pw *a, const struct l2vpn_pw *b)
{
	return if_cmp_name_func(a->ifname, b->ifname);
}

static inline int
l2vpn_if_compare(const struct l2vpn_if *a, const struct l2vpn_if *b)
{
	return if_cmp_name_func(a->ifname, b->ifname);
}

struct l2vpn *
l2vpn_new(const char *name)
{
	struct l2vpn *l2vpn;

	l2vpn = XCALLOC(MTYPE_L2VPN, sizeof(*l2vpn));

	strlcpy(l2vpn->name, name, sizeof(l2vpn->name));

	/* set default values */
	l2vpn->mtu = DEFAULT_L2VPN_MTU;
	l2vpn->pw_type = DEFAULT_PW_TYPE;

	RB_INIT(l2vpn_if_head, &l2vpn->if_tree);
	RB_INIT(l2vpn_pw_head, &l2vpn->pw_tree);
	RB_INIT(l2vpn_pw_head, &l2vpn->pw_inactive_tree);

	return l2vpn;
}


struct l2vpn *
l2vpn_find(struct l2vpn_head *l2vpn_tree, const char *name)
{
	struct l2vpn l2vpn;

	strlcpy(l2vpn.name, name, sizeof(l2vpn.name));
	return RB_FIND(l2vpn_head, l2vpn_tree, &l2vpn);
}

void
l2vpn_del(struct l2vpn *l2vpn)
{
	struct l2vpn_if *lif;
	struct l2vpn_pw *pw;

	while (!RB_EMPTY(l2vpn_if_head, &l2vpn->if_tree)) {
		lif = RB_ROOT(l2vpn_if_head, &l2vpn->if_tree);

		RB_REMOVE(l2vpn_if_head, &l2vpn->if_tree, lif);
		XFREE(MTYPE_L2VPN_IF, lif);
	}
	while (!RB_EMPTY(l2vpn_pw_head, &l2vpn->pw_tree)) {
		pw = RB_ROOT(l2vpn_pw_head, &l2vpn->pw_tree);

		RB_REMOVE(l2vpn_pw_head, &l2vpn->pw_tree, pw);
		XFREE(MTYPE_L2VPN_PWE, pw);
	}
	while (!RB_EMPTY(l2vpn_pw_head, &l2vpn->pw_inactive_tree)) {
		pw = RB_ROOT(l2vpn_pw_head, &l2vpn->pw_inactive_tree);

		RB_REMOVE(l2vpn_pw_head, &l2vpn->pw_inactive_tree, pw);
		XFREE(MTYPE_L2VPN_PWE, pw);
	}

	free(l2vpn);
}

struct l2vpn_pw *
l2vpn_pw_new(struct l2vpn *l2vpn, const char *ifname)
{
	struct l2vpn_pw *pw;

	pw = XCALLOC(MTYPE_L2VPN_PWE, sizeof(*pw));

	pw->l2vpn = l2vpn;
	strlcpy(pw->ifname, ifname, sizeof(pw->ifname));

	return pw;
}

struct l2vpn_if *
l2vpn_if_new(struct l2vpn *l2vpn, const char *ifname)
{
	struct l2vpn_if *lif;

	lif = XCALLOC(MTYPE_L2VPN_IF, sizeof(*lif));

	lif->l2vpn = l2vpn;
	strlcpy(lif->ifname, ifname, sizeof(lif->ifname));

	return lif;
}

struct l2vpn_pw *
l2vpn_pw_find_active(struct l2vpn *l2vpn, const char *ifname)
{
	struct l2vpn_pw s;

	strlcpy(s.ifname, ifname, sizeof(s.ifname));
	return RB_FIND(l2vpn_pw_head, &l2vpn->pw_tree, &s);
}

struct l2vpn_pw *
l2vpn_pw_find_inactive(struct l2vpn *l2vpn, const char *ifname)
{
	struct l2vpn_pw s;

	strlcpy(s.ifname, ifname, sizeof(s.ifname));
	return RB_FIND(l2vpn_pw_head, &l2vpn->pw_inactive_tree, &s);
}

/* clang-format on */

struct l2vpn_if *l2vpn_if_find(struct l2vpn *l2vpn, const char *ifname)
{
	struct l2vpn_if lif;

	strlcpy(lif.ifname, ifname, sizeof(lif.ifname));
	return RB_FIND(l2vpn_if_head, &l2vpn->if_tree, &lif);
}

struct l2vpn_pw *l2vpn_pw_find(struct l2vpn *l2vpn, const char *ifname)
{
	struct l2vpn_pw *pw;
	struct l2vpn_pw s;

	strlcpy(s.ifname, ifname, sizeof(s.ifname));
	pw = RB_FIND(l2vpn_pw_head, &l2vpn->pw_tree, &s);
	if (pw)
		return pw;
	return RB_FIND(l2vpn_pw_head, &l2vpn->pw_inactive_tree, &s);
}

int l2vpn_iface_is_configured(const char *ifname)
{
	struct l2vpn *l2vpn;

	RB_FOREACH (l2vpn, l2vpn_head, &l2vpn_tree_config) {
		if (l2vpn_if_find(l2vpn, ifname))
			return 1;
		if (l2vpn_pw_find(l2vpn, ifname))
			return 1;
	}

	return 0;
}

DEFPY_YANG_NOSH(l2vpn_command,
	l2vpn_cmd,
	"l2vpn WORD$l2vpn_name type vpls",
	"Configure l2vpn commands\n"
	"L2VPN name\n"
	"L2VPN type\n"
	"Virtual Private LAN Service\n")
{
	char xpath[XPATH_MAXLEN];
	int rv;

	snprintf(xpath, sizeof(xpath), "/frr-l2vpn:l2vpn/l2vpn-instance[name='%s'][type='vpls']",
		 l2vpn_name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	rv = nb_cli_apply_changes(vty, NULL);
	if (rv == CMD_SUCCESS)
		VTY_PUSH_XPATH(L2VPN_NODE, xpath);

	return rv;
}

DEFPY_YANG (no_l2vpn_command,
	no_l2vpn_cmd,
	"no l2vpn WORD$l2vpn_name type vpls",
	NO_STR
	"Configure l2vpn commands\n"
	"L2VPN name\n"
	"L2VPN type\n"
	"Virtual Private LAN Service\n")
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), "/frr-l2vpn:l2vpn/l2vpn-instance[name='%s'][type='vpls']",
		 l2vpn_name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG  (l2vpn_bridge,
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

DEFPY_YANG  (l2vpn_mtu,
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

DEFPY_YANG  (l2vpn_vc_type,
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

DEFPY_YANG  (l2vpn_member_interface,
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

DEFPY_YANG_NOSH(l2vpn_member_pseudowire,
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

DEFPY_YANG  (no_l2vpn_member_pseudowire,
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

DEFPY_YANG  (l2vpn_control_word,
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

DEFPY_YANG  (l2vpn_neighbor_address,
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

DEFPY_YANG  (l2vpn_neighbor_lsr_id,
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

DEFPY_YANG  (l2vpn_pw_id,
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

DEFPY_YANG  (l2vpn_pw_status_disable,
	     l2vpn_pw_status_disable_cmd,
	"[no] pw-status disable",
	NO_STR
	"Configure PW status\n"
	"Disable PW status\n")
{
	nb_cli_enqueue_change(vty, "./pw-status", NB_OP_MODIFY, no ? "true" : "false");

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
	install_node(&l2vpn_node);
	install_node(&l2vpn_pseudowire_node);
	install_default(L2VPN_NODE);
	install_default(L2VPN_PSEUDOWIRE_NODE);
	install_element(CONFIG_NODE, &l2vpn_cmd);
	install_element(CONFIG_NODE, &no_l2vpn_cmd);

	install_element(L2VPN_NODE, &l2vpn_bridge_cmd);
	install_element(L2VPN_NODE, &l2vpn_mtu_cmd);
	install_element(L2VPN_NODE, &l2vpn_vc_type_cmd);

	install_element(L2VPN_NODE, &l2vpn_member_interface_cmd);
	install_element(L2VPN_NODE, &l2vpn_member_pseudowire_cmd);
	install_element(L2VPN_NODE, &no_l2vpn_member_pseudowire_cmd);

	install_element(L2VPN_PSEUDOWIRE_NODE, &l2vpn_control_word_cmd);
	install_element(L2VPN_PSEUDOWIRE_NODE, &l2vpn_neighbor_address_cmd);
	install_element(L2VPN_PSEUDOWIRE_NODE, &l2vpn_neighbor_lsr_id_cmd);
	install_element(L2VPN_PSEUDOWIRE_NODE, &l2vpn_pw_id_cmd);
	install_element(L2VPN_PSEUDOWIRE_NODE, &l2vpn_pw_status_disable_cmd);
}

static void l2vpn_instance_show(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const char *name = yang_dnode_get_string(dnode, "./name");
	const char *pwtype = NULL;
	const char *bridge_name = NULL;
	uint16_t mtu;

	vty_out(vty, "l2vpn %s type vpls\n", name);

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
			.xpath = NULL,
		},
	}
};

void l2vpn_init(void)
{
	cmd_variable_handler_register(l2vpn_var_handlers);
	RB_INIT(l2vpn_head, &l2vpn_tree_config);
	l2vpn_cli_init();
}

void l2vpn_register_hook(void (*func_add)(const char *), void (*func_del)(const char *),
			 void (*func_event)(const char *),
			 bool (*func_iface_ok_for_l2vpn)(const char *))
{
	l2vpn_lib_master.add_hook = func_add;
	l2vpn_lib_master.del_hook = func_del;
	l2vpn_lib_master.event_hook = func_event;
	l2vpn_lib_master.iface_ok_for_l2vpn = func_iface_ok_for_l2vpn;
}
