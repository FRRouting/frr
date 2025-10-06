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

#include "ldpd/ldpd.h"
#include "ldpd/ldp_vty.h"
#include "ldpd/ldp_l2vpn.h"
#include "ldpd/lde.h"

/*
 * XPath: /frr-ldp-l2vpn:l2vpn/l2vpn-instance
 */
static int ldp_l2vpn_instance_create(struct nb_cb_create_args *args)
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
		l2vpn = l2vpn_find(vty_conf, l2vpn_name);
		if (l2vpn) {
			nb_running_set_entry(args->dnode, l2vpn);
			return NB_OK;
		}
		l2vpn = l2vpn_new(l2vpn_name);
		l2vpn->type = L2VPN_TYPE_VPLS;
		RB_INSERT(l2vpn_head, &vty_conf->l2vpn_tree, l2vpn);
		QOBJ_REG(l2vpn, l2vpn);
		nb_running_set_entry(args->dnode, l2vpn);

		if (l2vpn_lib_master.add_hook)
			(*l2vpn_lib_master.add_hook)(l2vpn_name);
		break;
	}

	return NB_OK;
}

static int ldp_l2vpn_instance_destroy(struct nb_cb_destroy_args *args)
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
		RB_REMOVE(l2vpn_head, &vty_conf->l2vpn_tree, l2vpn);
		l2vpn_del(l2vpn);
		if (l2vpn_lib_master.del_hook)
			(*l2vpn_lib_master.del_hook)(name);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-ldp-l2vpn:l2vpn/l2vpn-instance/pw-type
 */
static int ldp_l2vpn_instance_pw_type_modify(struct nb_cb_modify_args *args)
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

static int ldp_l2vpn_instance_pw_type_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-ldp-l2vpn:l2vpn/l2vpn-instance/mtu
 */
static int ldp_l2vpn_instance_mtu_modify(struct nb_cb_modify_args *args)
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

static int ldp_l2vpn_instance_mtu_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-ldp-l2vpn:l2vpn/l2vpn-instance/bridge-interface
 */
static int ldp_l2vpn_instance_bridge_interface_modify(struct nb_cb_modify_args *args)
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

static int ldp_l2vpn_instance_bridge_interface_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-ldp-l2vpn:l2vpn/l2vpn-instance/member-interface
 */
static int ldp_l2vpn_instance_member_interface_create(struct nb_cb_create_args *args)
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

static int ldp_l2vpn_instance_member_interface_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-ldp-l2vpn:l2vpn/l2vpn-instance/member-pseudowire
 */
static int ldp_l2vpn_instance_member_pseudowire_create(struct nb_cb_create_args *args)
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

static int ldp_l2vpn_instance_member_pseudowire_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-ldp-l2vpn:l2vpn/l2vpn-instance/member-pseudowire/neighbor-lsr-id
 */
static int
ldp_l2vpn_instance_member_pseudowire_neighbor_lsr_id_modify(struct nb_cb_modify_args *args)
{
	struct l2vpn_pw *pw;
	struct ipaddr lsr_id;
	struct l2vpn *l2vpn;

	yang_dnode_get_ip(&lsr_id, args->dnode, NULL);
	switch (args->event) {
	case NB_EV_VALIDATE:
		if (lsr_id.ipa_type != IPADDR_V4 || bad_addr_v4(lsr_id.ip._v4_addr)) {
			snprintf(args->errmsg, args->errmsg_len, "%% Malformed address");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		pw = nb_running_get_entry(args->dnode, NULL, true);
		pw->lsr_id = lsr_id.ip._v4_addr;
		l2vpn = nb_running_get_entry(args->dnode, "../.", true);

		if (l2vpn_lib_master.event_hook)
			(*l2vpn_lib_master.event_hook)(l2vpn->name);
		break;
	}

	return NB_OK;
}

static int
ldp_l2vpn_instance_member_pseudowire_neighbor_lsr_id_destroy(struct nb_cb_destroy_args *args)
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
		pw->lsr_id.s_addr = INADDR_ANY;
		l2vpn = nb_running_get_entry(args->dnode, "../.", true);

		if (l2vpn_lib_master.event_hook)
			(*l2vpn_lib_master.event_hook)(l2vpn->name);
		break;
	}
	return NB_OK;
}

/*
 * XPath: /frr-ldp-l2vpn:l2vpn/l2vpn-instance/member-pseudowire/pw-id
 */
static int ldp_l2vpn_instance_member_pseudowire_pw_id_modify(struct nb_cb_modify_args *args)
{
	struct l2vpn_pw *pw;
	uint32_t pw_id;
	struct l2vpn *l2vpn;

	pw_id = yang_dnode_get_uint32(args->dnode, NULL);
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		pw = nb_running_get_entry(args->dnode, NULL, true);
		pw->pwid = pw_id;
		l2vpn = nb_running_get_entry(args->dnode, "../.", true);

		if (l2vpn_lib_master.event_hook)
			(*l2vpn_lib_master.event_hook)(l2vpn->name);
		break;
	}

	return NB_OK;
}

static int ldp_l2vpn_instance_member_pseudowire_pw_id_destroy(struct nb_cb_destroy_args *args)
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
		pw->pwid = 0;
		l2vpn = nb_running_get_entry(args->dnode, "../.", true);

		if (l2vpn_lib_master.event_hook)
			(*l2vpn_lib_master.event_hook)(l2vpn->name);
		break;
	}
	return NB_OK;
}

/*
 * XPath: /frr-ldp-l2vpn:l2vpn/l2vpn-instance/member-pseudowire/neighbor-address
 */
static int
ldp_l2vpn_instance_member_pseudowire_neighbor_address_modify(struct nb_cb_modify_args *args)
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
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		pw = nb_running_get_entry(args->dnode, NULL, true);
		if (nbr_id.ipa_type == IPADDR_V4) {
			pw->af = AF_INET;
			pw->addr.v4 = nbr_id.ip._v4_addr;
		} else {
			pw->af = AF_INET6;
			IPV6_ADDR_COPY(&pw->addr.v6, &nbr_id.ip._v4_addr);
		}
		pw->flags |= F_PW_STATIC_NBR_ADDR;
		l2vpn = nb_running_get_entry(args->dnode, "../.", true);

		if (l2vpn_lib_master.event_hook)
			(*l2vpn_lib_master.event_hook)(l2vpn->name);
		break;
	}

	return NB_OK;
}

static int
ldp_l2vpn_instance_member_pseudowire_neighbor_address_destroy(struct nb_cb_destroy_args *args)
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
 * XPath: /frr-ldp-l2vpn:l2vpn/l2vpn-instance/member-pseudowire/control-word
 */
static int ldp_l2vpn_instance_member_pseudowire_control_word_modify(struct nb_cb_modify_args *args)
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

/*
 * XPath: /frr-ldp-l2vpn:l2vpn/l2vpn-instance/member-pseudowire/pw-status
 */
static int ldp_l2vpn_instance_member_pseudowire_pw_status_modify(struct nb_cb_modify_args *args)
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

const struct frr_yang_module_info frr_ldp_l2vpn = {
	.name = "frr-ldp-l2vpn",
	.nodes = {
		{
			.xpath = "/frr-ldp-l2vpn:l2vpn/l2vpn-instance",
			.cbs = {
				.create = ldp_l2vpn_instance_create,
				.destroy = ldp_l2vpn_instance_destroy,
			}
		},
		{
			.xpath = "/frr-ldp-l2vpn:l2vpn/l2vpn-instance/pw-type",
			.cbs = {
				.modify = ldp_l2vpn_instance_pw_type_modify,
				.destroy = ldp_l2vpn_instance_pw_type_destroy,
			}
		},
		{
			.xpath = "/frr-ldp-l2vpn:l2vpn/l2vpn-instance/mtu",
			.cbs = {
				.modify = ldp_l2vpn_instance_mtu_modify,
				.destroy = ldp_l2vpn_instance_mtu_destroy,
			}
		},
		{
			.xpath = "/frr-ldp-l2vpn:l2vpn/l2vpn-instance/bridge-interface",
			.cbs = {
				.modify = ldp_l2vpn_instance_bridge_interface_modify,
				.destroy = ldp_l2vpn_instance_bridge_interface_destroy,
			}
		},
		{
			.xpath = "/frr-ldp-l2vpn:l2vpn/l2vpn-instance/member-interface",
			.cbs = {
				.create = ldp_l2vpn_instance_member_interface_create,
				.destroy = ldp_l2vpn_instance_member_interface_destroy,
			}
		},
		{
			.xpath = "/frr-ldp-l2vpn:l2vpn/l2vpn-instance/member-pseudowire",
			.cbs = {
				.create = ldp_l2vpn_instance_member_pseudowire_create,
				.destroy = ldp_l2vpn_instance_member_pseudowire_destroy,
			}
		},
		{
			.xpath = "/frr-ldp-l2vpn:l2vpn/l2vpn-instance/member-pseudowire/neighbor-lsr-id",
			.cbs = {
				.modify = ldp_l2vpn_instance_member_pseudowire_neighbor_lsr_id_modify,
				.destroy = ldp_l2vpn_instance_member_pseudowire_neighbor_lsr_id_destroy,
			}
		},
		{
			.xpath = "/frr-ldp-l2vpn:l2vpn/l2vpn-instance/member-pseudowire/neighbor-address",
			.cbs = {
				.modify = ldp_l2vpn_instance_member_pseudowire_neighbor_address_modify,
				.destroy = ldp_l2vpn_instance_member_pseudowire_neighbor_address_destroy,
			}
		},
		{
			.xpath = "/frr-ldp-l2vpn:l2vpn/l2vpn-instance/member-pseudowire/pw-id",
			.cbs = {
				.modify = ldp_l2vpn_instance_member_pseudowire_pw_id_modify,
				.destroy = ldp_l2vpn_instance_member_pseudowire_pw_id_destroy,
			}
		},
		{
			.xpath = "/frr-ldp-l2vpn:l2vpn/l2vpn-instance/member-pseudowire/control-word",
			.cbs = {
				.modify = ldp_l2vpn_instance_member_pseudowire_control_word_modify,
			}
		},
		{
			.xpath = "/frr-ldp-l2vpn:l2vpn/l2vpn-instance/member-pseudowire/pw-status",
			.cbs = {
				.modify = ldp_l2vpn_instance_member_pseudowire_pw_status_modify,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
