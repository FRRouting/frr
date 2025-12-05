// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * LDP L2VPN northbound implementation.
 *
 * Copyright (C) 2025 6WIND
 */

#include <zebra.h>

#include "lib/command.h"
#include "lib/log.h"
#include "lib/northbound.h"
#include "lib/ipaddr.h"
#include "lib/l2vpn.h"

static void l2vpn_instance_show(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const char *name = yang_dnode_get_string(dnode, "./name");

	vty_out(vty, "l2vpn %s type vpls\n", name);
}

static void l2vpn_instance_show_end(struct vty *vty, const struct lyd_node *dnode)
{
	vty_out(vty, "exit\n");
	vty_out(vty, "!\n");
}

static void l2vpn_instance_pw_type_show(struct vty *vty, const struct lyd_node *dnode,
					bool show_defaults)
{
	const char *pwtype = yang_dnode_get_string(dnode, NULL);

	if (pwtype && !strcmp(pwtype, "ethernet-tagged"))
		vty_out(vty, " vc type %s\n", pwtype);
}

static void l2vpn_instance_member_pseudowire_show(struct vty *vty, const struct lyd_node *dnode,
						  bool show_defaults)
{
	const char *name = yang_dnode_get_string(dnode, "./interface");

	vty_out(vty, " member pseudowire %s\n", name);
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

static void l2vpn_instance_bridge_interface_show(struct vty *vty, const struct lyd_node *dnode,
						 bool show_defaults)
{
	const char *name = yang_dnode_get_string(dnode, NULL);

	vty_out(vty, " bridge %s\n", name);
}

static void l2vpn_instance_mtu_show(struct vty *vty, const struct lyd_node *dnode,
				    bool show_defaults)
{
	const uint16_t mtu = yang_dnode_get_uint16(dnode, NULL);

	if (mtu != DEFAULT_L2VPN_MTU)
		vty_out(vty, " mtu %d\n", mtu);
}

static void l2vpn_instance_member_pseudowire_neighbor_lsr_id_show(struct vty *vty,
								  const struct lyd_node *dnode,
								  bool show_defaults)
{
	struct ipaddr lsr_id;

	yang_dnode_get_ip(&lsr_id, dnode, NULL);
	if (lsr_id.ipaddr_v4.s_addr != INADDR_ANY)
		vty_out(vty, "  neighbor lsr-id %pI4\n", &lsr_id.ipaddr_v4);
	else
		vty_out(vty, "  ! Incomplete config, specify a neighbor lsr-id\n");
}

static void l2vpn_instance_member_pseudowire_neighbor_address_show(struct vty *vty,
								   const struct lyd_node *dnode,
								   bool show_defaults)
{
	struct ipaddr address;

	yang_dnode_get_ip(&address, dnode, NULL);
	if (address.ipa_type == IPADDR_V4)
		vty_out(vty, "  neighbor address %pI4\n", &address.ipaddr_v4);
	else if (address.ipa_type == IPADDR_V6)
		vty_out(vty, "  neighbor address %pI6\n", &address.ipaddr_v6);
}

static void l2vpn_instance_member_pseudowire_pw_id_show(struct vty *vty,
							const struct lyd_node *dnode,
							bool show_defaults)
{
	uint32_t pw_id;

	pw_id = yang_dnode_get_uint32(dnode, NULL);

	if (pw_id != 0)
		vty_out(vty, "  pw-id %u\n", pw_id);
	else
		vty_out(vty, "  ! Incomplete config, specify a pw-id\n");
}

static void l2vpn_instance_member_pseudowire_control_word_show(struct vty *vty,
							       const struct lyd_node *dnode,
							       bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "  control-word exclude\n");
}

static void l2vpn_instance_member_pseudowire_pw_status_show(struct vty *vty,
							    const struct lyd_node *dnode,
							    bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "  pw-status disable\n");
}


/*
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance
 */
static int l2vpn_instance_create(struct nb_cb_create_args *args)
{
	const char *l2vpn_name;
	struct l2vpn *l2vpn;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		l2vpn_name = yang_dnode_get_string(args->dnode, "name");
		l2vpn = l2vpn_find(&l2vpn_tree_config, l2vpn_name);
		if (l2vpn) {
			nb_running_set_entry(args->dnode, l2vpn);
			return NB_OK;
		}
		l2vpn = l2vpn_new(l2vpn_name);
		l2vpn->type = L2VPN_TYPE_VPLS;
		RB_INSERT(l2vpn_head, &l2vpn_tree_config, l2vpn);
		QOBJ_REG(l2vpn, l2vpn);
		nb_running_set_entry(args->dnode, l2vpn);

		if (l2vpn_lib_master.add_hook)
			(*l2vpn_lib_master.add_hook)(l2vpn_name);
		break;
	}

	return NB_OK;
}

static int l2vpn_instance_destroy(struct nb_cb_destroy_args *args)
{
	struct l2vpn *l2vpn;
	struct l2vpn_if *lif;
	struct l2vpn_pw *pw;
	char name[L2VPN_NAME_LEN];

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		l2vpn = nb_running_unset_entry(args->dnode);
		snprintf(name, sizeof(name), "%s", l2vpn->name);
		RB_FOREACH (lif, l2vpn_if_head, &l2vpn->if_tree)
			QOBJ_UNREG(lif);
		RB_FOREACH (pw, l2vpn_pw_head, &l2vpn->pw_tree)
			QOBJ_UNREG(pw);
		RB_FOREACH (pw, l2vpn_pw_head, &l2vpn->pw_inactive_tree)
			QOBJ_UNREG(pw);
		QOBJ_UNREG(l2vpn);
		RB_REMOVE(l2vpn_head, &l2vpn_tree_config, l2vpn);
		l2vpn_del(l2vpn);
		if (l2vpn_lib_master.del_hook)
			(*l2vpn_lib_master.del_hook)(name);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance/pw-type
 */
static int l2vpn_instance_pw_type_modify(struct nb_cb_modify_args *args)
{
	struct l2vpn *l2vpn;
	const char *pw_type;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		l2vpn = nb_running_get_entry(args->dnode, NULL, true);
		pw_type = yang_dnode_get_string(args->dnode, NULL);
		if (strcmp(pw_type, "ethernet") == 0)
			l2vpn->pw_type = PW_TYPE_ETHERNET;
		else
			l2vpn->pw_type = PW_TYPE_ETHERNET_TAGGED;

		if (l2vpn_lib_master.event_hook)
			(*l2vpn_lib_master.event_hook)(l2vpn->name);
		break;
	}

	return NB_OK;
}

static int l2vpn_instance_pw_type_destroy(struct nb_cb_destroy_args *args)
{
	struct l2vpn *l2vpn;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		l2vpn = nb_running_get_entry(args->dnode, NULL, true);
		l2vpn->pw_type = DEFAULT_PW_TYPE;

		if (l2vpn_lib_master.event_hook)
			(*l2vpn_lib_master.event_hook)(l2vpn->name);
		break;
	}
	return NB_OK;
}

/*
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance/mtu
 */
static int l2vpn_instance_mtu_modify(struct nb_cb_modify_args *args)
{
	struct l2vpn *l2vpn;
	uint16_t mtu;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		l2vpn = nb_running_get_entry(args->dnode, NULL, true);
		mtu = yang_dnode_get_uint16(args->dnode, NULL);
		l2vpn->mtu = mtu;

		if (l2vpn_lib_master.event_hook)
			(*l2vpn_lib_master.event_hook)(l2vpn->name);
		break;
	}

	return NB_OK;
}

static int l2vpn_instance_mtu_destroy(struct nb_cb_destroy_args *args)
{
	struct l2vpn *l2vpn;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		l2vpn = nb_running_get_entry(args->dnode, NULL, true);
		l2vpn->mtu = DEFAULT_L2VPN_MTU;

		if (l2vpn_lib_master.event_hook)
			(*l2vpn_lib_master.event_hook)(l2vpn->name);
		break;
	}
	return NB_OK;
}

/*
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance/bridge-interface
 */
static int l2vpn_instance_bridge_interface_modify(struct nb_cb_modify_args *args)
{
	struct l2vpn *l2vpn;
	const char *ifname;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		l2vpn = nb_running_get_entry(args->dnode, NULL, true);
		ifname = yang_dnode_get_string(args->dnode, NULL);
		strlcpy(l2vpn->br_ifname, ifname, sizeof(l2vpn->br_ifname));

		if (l2vpn_lib_master.event_hook)
			(*l2vpn_lib_master.event_hook)(l2vpn->name);
		break;
	}

	return NB_OK;
}

static int l2vpn_instance_bridge_interface_destroy(struct nb_cb_destroy_args *args)
{
	struct l2vpn *l2vpn;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		l2vpn = nb_running_get_entry(args->dnode, NULL, true);
		memset(l2vpn->br_ifname, 0, sizeof(l2vpn->br_ifname));

		if (l2vpn_lib_master.event_hook)
			(*l2vpn_lib_master.event_hook)(l2vpn->name);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance/member-interface
 */
static int l2vpn_instance_member_interface_create(struct nb_cb_create_args *args)
{
	struct l2vpn *l2vpn;
	struct l2vpn_if *lif;
	const char *ifname;

	ifname = yang_dnode_get_string(args->dnode, "interface");
	switch (args->event) {
	case NB_EV_VALIDATE:
		if ((l2vpn_lib_master.iface_ok_for_l2vpn &&
		     (*l2vpn_lib_master.iface_ok_for_l2vpn)(ifname)) ||
		    l2vpn_iface_is_configured(ifname)) {
			snprintf(args->errmsg, args->errmsg_len, "%% Interface is already in use");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		l2vpn = nb_running_get_entry(args->dnode, "../.", true);
		lif = l2vpn_if_find(l2vpn, ifname);
		if (lif) {
			nb_running_set_entry(args->dnode, lif);
			return NB_OK;
		}
		lif = l2vpn_if_new(l2vpn, ifname);
		RB_INSERT(l2vpn_if_head, &l2vpn->if_tree, lif);
		QOBJ_REG(lif, l2vpn_if);
		nb_running_set_entry(args->dnode, lif);

		if (l2vpn_lib_master.event_hook)
			(*l2vpn_lib_master.event_hook)(l2vpn->name);
		break;
	}

	return NB_OK;
}

static int l2vpn_instance_member_interface_destroy(struct nb_cb_destroy_args *args)
{
	struct l2vpn *l2vpn;
	struct l2vpn_if *lif;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		l2vpn = nb_running_get_entry(args->dnode, "../.", true);
		lif = nb_running_unset_entry(args->dnode);
		if (!lif)
			return NB_OK;

		QOBJ_UNREG(lif);
		RB_REMOVE(l2vpn_if_head, &l2vpn->if_tree, lif);
		free(lif);

		if (l2vpn_lib_master.event_hook)
			(*l2vpn_lib_master.event_hook)(l2vpn->name);
		break;
	}
	return NB_OK;
}

/*
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance/member-pseudowire
 */
static int l2vpn_instance_member_pseudowire_create(struct nb_cb_create_args *args)
{
	struct l2vpn *l2vpn;
	struct l2vpn_pw *pw;
	const char *ifname;

	ifname = yang_dnode_get_string(args->dnode, "interface");
	switch (args->event) {
	case NB_EV_VALIDATE:
		if ((l2vpn_lib_master.iface_ok_for_l2vpn &&
		     (*l2vpn_lib_master.iface_ok_for_l2vpn)(ifname)) ||
		    l2vpn_iface_is_configured(ifname)) {
			snprintf(args->errmsg, args->errmsg_len, "%% Interface is already in use");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		l2vpn = nb_running_get_entry(args->dnode, "../.", true);
		pw = l2vpn_pw_find(l2vpn, ifname);
		if (pw) {
			nb_running_set_entry(args->dnode, pw);
			return NB_OK;
		}
		pw = l2vpn_pw_new(l2vpn, ifname);
		pw->flags = F_PW_STATUSTLV_CONF | F_PW_CWORD_CONF;
		RB_INSERT(l2vpn_pw_head, &l2vpn->pw_inactive_tree, pw);
		QOBJ_REG(pw, l2vpn_pw);

		nb_running_set_entry(args->dnode, pw);

		if (l2vpn_lib_master.event_hook)
			(*l2vpn_lib_master.event_hook)(l2vpn->name);
		break;
	}

	return NB_OK;
}

static int l2vpn_instance_member_pseudowire_destroy(struct nb_cb_destroy_args *args)
{
	struct l2vpn *l2vpn;
	struct l2vpn_pw *pw;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		l2vpn = nb_running_get_entry(args->dnode, "../.", true);
		pw = nb_running_unset_entry(args->dnode);
		if (!pw)
			return NB_OK;

		QOBJ_UNREG(pw);
		if (pw->lsr_id.s_addr == INADDR_ANY || pw->pwid == 0)
			RB_REMOVE(l2vpn_pw_head, &l2vpn->pw_inactive_tree, pw);
		else
			RB_REMOVE(l2vpn_pw_head, &l2vpn->pw_tree, pw);
		free(pw);

		if (l2vpn_lib_master.event_hook)
			(*l2vpn_lib_master.event_hook)(l2vpn->name);
		break;
	}
	return NB_OK;
}

/*
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance/member-pseudowire/neighbor-lsr-id
 */
static int l2vpn_instance_member_pseudowire_neighbor_lsr_id_modify(struct nb_cb_modify_args *args)
{
	struct l2vpn_pw *pw;
	struct ipaddr lsr_id;
	struct l2vpn *l2vpn;

	pw = nb_running_get_entry(args->dnode, NULL, true);
	yang_dnode_get_ip(&lsr_id, args->dnode, NULL);
	switch (args->event) {
	case NB_EV_VALIDATE:
		if (lsr_id.ipa_type != IPADDR_V4 || bad_addr_v4(lsr_id.ip._v4_addr)) {
			snprintf(args->errmsg, args->errmsg_len, "%% Malformed address");
			return NB_ERR_VALIDATION;
		}
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		pw->lsr_id = lsr_id.ip._v4_addr;
		l2vpn = nb_running_get_entry(args->dnode, "../.", true);

		if (l2vpn_lib_master.event_hook)
			(*l2vpn_lib_master.event_hook)(l2vpn->name);
		break;
	}

	return NB_OK;
}

static int l2vpn_instance_member_pseudowire_neighbor_lsr_id_destroy(struct nb_cb_destroy_args *args)
{
	struct l2vpn_pw *pw;
	struct l2vpn *l2vpn;

	pw = nb_running_get_entry(args->dnode, NULL, true);
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		pw = nb_running_get_entry(args->dnode, NULL, true);
		pw->lsr_id.s_addr = INADDR_ANY;
		l2vpn = nb_running_get_entry(args->dnode, "../.", true);

		if (l2vpn_lib_master.event_hook)
			(*l2vpn_lib_master.event_hook)(l2vpn->name);
		break;
	}
	return NB_OK;
}

/*
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance/member-pseudowire/pw-id
 */
static int l2vpn_instance_member_pseudowire_pw_id_modify(struct nb_cb_modify_args *args)
{
	struct l2vpn_pw *pw;
	uint32_t pw_id;
	struct l2vpn *l2vpn;

	pw = nb_running_get_entry(args->dnode, NULL, true);
	pw_id = yang_dnode_get_uint32(args->dnode, NULL);
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		pw->pwid = pw_id;
		l2vpn = nb_running_get_entry(args->dnode, "../.", true);

		if (l2vpn_lib_master.event_hook)
			(*l2vpn_lib_master.event_hook)(l2vpn->name);
		break;
	}

	return NB_OK;
}

static int l2vpn_instance_member_pseudowire_pw_id_destroy(struct nb_cb_destroy_args *args)
{
	struct l2vpn_pw *pw;
	struct l2vpn *l2vpn;

	pw = nb_running_get_entry(args->dnode, NULL, true);
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		pw = nb_running_get_entry(args->dnode, NULL, true);
		pw->pwid = 0;
		l2vpn = nb_running_get_entry(args->dnode, "../.", true);

		if (l2vpn_lib_master.event_hook)
			(*l2vpn_lib_master.event_hook)(l2vpn->name);
		break;
	}
	return NB_OK;
}

/*
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance/member-pseudowire/neighbor-address
 */
static int l2vpn_instance_member_pseudowire_neighbor_address_modify(struct nb_cb_modify_args *args)
{
	struct l2vpn_pw *pw;
	struct ipaddr nbr_id;
	struct l2vpn *l2vpn;

	yang_dnode_get_ip(&nbr_id, args->dnode, NULL);
	switch (args->event) {
	case NB_EV_VALIDATE:
		if ((nbr_id.ipa_type == IPADDR_V4 && bad_addr_v4(nbr_id.ip._v4_addr)) ||
		    (nbr_id.ipa_type == IPADDR_V6 && bad_addr_v6(&nbr_id.ip._v6_addr)) ||
		    (nbr_id.ipa_type == IPADDR_NONE)) {
			snprintf(args->errmsg, args->errmsg_len, "%% Malformed address");
			return NB_ERR_VALIDATION;
		}
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		pw = nb_running_get_entry(args->dnode, NULL, true);
		if (nbr_id.ipa_type == IPADDR_V4) {
			pw->af = AF_INET;
			pw->addr.ipv4 = nbr_id.ip._v4_addr;
		} else {
			pw->af = AF_INET6;
			IPV6_ADDR_COPY(&pw->addr.ipv6, &nbr_id.ip._v4_addr);
		}
		pw->flags |= F_PW_STATIC_NBR_ADDR;
		l2vpn = nb_running_get_entry(args->dnode, "../.", true);

		if (l2vpn_lib_master.event_hook)
			(*l2vpn_lib_master.event_hook)(l2vpn->name);
		break;
	}

	return NB_OK;
}

static int l2vpn_instance_member_pseudowire_neighbor_address_destroy(struct nb_cb_destroy_args *args)
{
	struct l2vpn_pw *pw;
	struct l2vpn *l2vpn;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		pw = nb_running_get_entry(args->dnode, NULL, true);
		pw->af = AF_UNSPEC;
		memset(&pw->addr, 0, sizeof(pw->addr));
		pw->flags &= ~F_PW_STATIC_NBR_ADDR;
		l2vpn = nb_running_get_entry(args->dnode, "../.", true);

		if (l2vpn_lib_master.event_hook)
			(*l2vpn_lib_master.event_hook)(l2vpn->name);
		break;
	}
	return NB_OK;
}

/*
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance/member-pseudowire/control-word
 */
static int l2vpn_instance_member_pseudowire_control_word_modify(struct nb_cb_modify_args *args)
{
	struct l2vpn_pw *pw;
	struct l2vpn *l2vpn;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		pw = nb_running_get_entry(args->dnode, NULL, true);
		if (yang_dnode_get_bool(args->dnode, NULL))
			pw->flags &= ~F_PW_CWORD_CONF;
		else
			pw->flags |= F_PW_CWORD_CONF;
		l2vpn = nb_running_get_entry(args->dnode, "../.", true);

		if (l2vpn_lib_master.event_hook)
			(*l2vpn_lib_master.event_hook)(l2vpn->name);
		break;
	}

	return NB_OK;
}

static int l2vpn_instance_member_pseudowire_control_word_destroy(struct nb_cb_destroy_args *args)
{
	struct l2vpn_pw *pw;
	struct l2vpn *l2vpn;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		pw = nb_running_get_entry(args->dnode, NULL, true);
		pw->flags |= F_PW_CWORD_CONF;
		l2vpn = nb_running_get_entry(args->dnode, "../.", true);

		if (l2vpn_lib_master.event_hook)
			(*l2vpn_lib_master.event_hook)(l2vpn->name);
		break;
	}
	return NB_OK;
}

/*
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance/member-pseudowire/pw-status
 */
static int l2vpn_instance_member_pseudowire_pw_status_modify(struct nb_cb_modify_args *args)
{
	struct l2vpn_pw *pw;
	struct l2vpn *l2vpn;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		pw = nb_running_get_entry(args->dnode, NULL, true);
		if (yang_dnode_get_bool(args->dnode, NULL))
			pw->flags &= ~F_PW_STATUSTLV_CONF;
		else
			pw->flags |= F_PW_STATUSTLV_CONF;
		l2vpn = nb_running_get_entry(args->dnode, "../.", true);

		if (l2vpn_lib_master.event_hook)
			(*l2vpn_lib_master.event_hook)(l2vpn->name);
		break;
	}

	return NB_OK;
}

static int l2vpn_instance_member_pseudowire_pw_status_destroy(struct nb_cb_destroy_args *args)
{
	struct l2vpn_pw *pw;
	struct l2vpn *l2vpn;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		pw = nb_running_get_entry(args->dnode, NULL, true);
		pw->flags |= F_PW_STATUSTLV_CONF;
		l2vpn = nb_running_get_entry(args->dnode, "../.", true);

		if (l2vpn_lib_master.event_hook)
			(*l2vpn_lib_master.event_hook)(l2vpn->name);
		break;
	}
	return NB_OK;
}

const struct frr_yang_module_info frr_l2vpn = {
	.name = "frr-l2vpn",
	.ignore_cfg_cbs = true,
	.nodes = {
		{
			.xpath = "/frr-l2vpn:l2vpn/l2vpn-instance",
			.cbs = {
				.create = l2vpn_instance_create,
				.destroy = l2vpn_instance_destroy,
                                .cli_show = l2vpn_instance_show,
                                .cli_show_end = l2vpn_instance_show_end,
			}
		},
		{
			.xpath = "/frr-l2vpn:l2vpn/l2vpn-instance/pw-type",
			.cbs = {
				.modify = l2vpn_instance_pw_type_modify,
				.destroy = l2vpn_instance_pw_type_destroy,
				.cli_show = l2vpn_instance_pw_type_show,
			}
		},
		{
			.xpath = "/frr-l2vpn:l2vpn/l2vpn-instance/mtu",
			.cbs = {
				.modify = l2vpn_instance_mtu_modify,
				.destroy = l2vpn_instance_mtu_destroy,
				.cli_show = l2vpn_instance_mtu_show,
			}
		},
		{
			.xpath = "/frr-l2vpn:l2vpn/l2vpn-instance/bridge-interface",
			.cbs = {
				.modify = l2vpn_instance_bridge_interface_modify,
				.destroy = l2vpn_instance_bridge_interface_destroy,
				.cli_show = l2vpn_instance_bridge_interface_show,
			}
		},
		{
			.xpath = "/frr-l2vpn:l2vpn/l2vpn-instance/member-interface",
			.cbs = {
				.create = l2vpn_instance_member_interface_create,
				.destroy = l2vpn_instance_member_interface_destroy,
				.cli_show = l2vpn_instance_member_interface_show,
			}
		},
		{
			.xpath = "/frr-l2vpn:l2vpn/l2vpn-instance/member-pseudowire",
			.cbs = {
				.create = l2vpn_instance_member_pseudowire_create,
				.destroy = l2vpn_instance_member_pseudowire_destroy,
                                .cli_show = l2vpn_instance_member_pseudowire_show,
                                .cli_show_end = l2vpn_instance_member_pseudowire_show_end,
			}
		},
		{
			.xpath = "/frr-l2vpn:l2vpn/l2vpn-instance/member-pseudowire/neighbor-lsr-id",
			.cbs = {
				.modify = l2vpn_instance_member_pseudowire_neighbor_lsr_id_modify,
				.destroy = l2vpn_instance_member_pseudowire_neighbor_lsr_id_destroy,
                                .cli_show = l2vpn_instance_member_pseudowire_neighbor_lsr_id_show,
			}
		},
		{
			.xpath = "/frr-l2vpn:l2vpn/l2vpn-instance/member-pseudowire/neighbor-address",
			.cbs = {
				.modify = l2vpn_instance_member_pseudowire_neighbor_address_modify,
				.destroy = l2vpn_instance_member_pseudowire_neighbor_address_destroy,
                                .cli_show = l2vpn_instance_member_pseudowire_neighbor_address_show,
			}
		},
		{
			.xpath = "/frr-l2vpn:l2vpn/l2vpn-instance/member-pseudowire/pw-id",
			.cbs = {
				.modify = l2vpn_instance_member_pseudowire_pw_id_modify,
				.destroy = l2vpn_instance_member_pseudowire_pw_id_destroy,
                                .cli_show = l2vpn_instance_member_pseudowire_pw_id_show,
			}
		},
		{
			.xpath = "/frr-l2vpn:l2vpn/l2vpn-instance/member-pseudowire/control-word",
			.cbs = {
				.modify = l2vpn_instance_member_pseudowire_control_word_modify,
				.destroy = l2vpn_instance_member_pseudowire_control_word_destroy,
                                .cli_show = l2vpn_instance_member_pseudowire_control_word_show,
			}
		},
		{
			.xpath = "/frr-l2vpn:l2vpn/l2vpn-instance/member-pseudowire/pw-status",
			.cbs = {
				.modify = l2vpn_instance_member_pseudowire_pw_status_modify,
				.destroy = l2vpn_instance_member_pseudowire_pw_status_destroy,
                                .cli_show = l2vpn_instance_member_pseudowire_pw_status_show,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
