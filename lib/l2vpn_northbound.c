// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * L2VPN northbound implementation.
 *
 * Copyright 2025 6WIND S.A.
 */

#include <zebra.h>

#include "lib/command.h"
#include "lib/log.h"
#include "lib/northbound.h"
#include "lib/l2vpn_svc.h"

/*
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance
 */
static int l2vpn_instance_create(struct nb_cb_create_args *args)
{
	const char *l2vpn_name;
	struct l2vpn *l2vpn;
	uint16_t l2_type;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		l2vpn_name = yang_dnode_get_string(args->dnode, "name");
		l2_type = yang_dnode_get_enum(args->dnode, "type");
		l2vpn = l2vpn_find(&l2vpn_tree_config, l2vpn_name, l2_type);
		if (l2vpn) {
			nb_running_set_entry(args->dnode, l2vpn);
			return NB_OK;
		}
		l2vpn = l2vpn_new(l2vpn_name);
		l2vpn->type = l2_type;
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
	struct l2vpn_svc *svc;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		l2vpn = nb_running_unset_entry(args->dnode);
		if (l2vpn_lib_master.del_hook)
			(*l2vpn_lib_master.del_hook)(l2vpn->name);
		RB_FOREACH (lif, l2vpn_if_head, &l2vpn->if_tree)
			QOBJ_UNREG(lif);
		RB_FOREACH (svc, l2vpn_svc_head, &l2vpn->svc_tree)
			QOBJ_UNREG(svc);
		RB_FOREACH (svc, l2vpn_svc_head, &l2vpn->svc_inactive_tree)
			QOBJ_UNREG(svc);
		QOBJ_UNREG(l2vpn);
		RB_REMOVE(l2vpn_head, &l2vpn_tree_config, l2vpn);

		l2vpn_del(l2vpn);

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

		if (l2vpn_lib_master.add_hook)
			(*l2vpn_lib_master.add_hook)(l2vpn->name);
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

		if (l2vpn_lib_master.del_hook)
			(*l2vpn_lib_master.del_hook)(l2vpn->name);
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

		if (l2vpn_lib_master.add_hook)
			(*l2vpn_lib_master.add_hook)(l2vpn->name);
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

		if (l2vpn_lib_master.del_hook)
			(*l2vpn_lib_master.del_hook)(l2vpn->name);
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

		if (l2vpn_lib_master.add_hook)
			(*l2vpn_lib_master.add_hook)(l2vpn->name);
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

		if (l2vpn_lib_master.del_hook)
			(*l2vpn_lib_master.del_hook)(l2vpn->name);

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
		l2vpn = nb_running_get_entry(args->dnode, NULL, true);
		lif = l2vpn_if_find(l2vpn, ifname);
		if (lif)
			return NB_OK;
		lif = l2vpn_if_new(l2vpn, ifname);
		RB_INSERT(l2vpn_if_head, &l2vpn->if_tree, lif);
		QOBJ_REG(lif, l2vpn_if);

		if (l2vpn_lib_master.add_hook)
			(*l2vpn_lib_master.add_hook)(l2vpn->name);
		break;
	}

	return NB_OK;
}

static int l2vpn_instance_member_interface_destroy(struct nb_cb_destroy_args *args)
{
	const char *ifname;
	struct l2vpn *l2vpn;
	struct l2vpn_if *lif;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		ifname = yang_dnode_get_string(args->dnode, "interface");
		l2vpn = nb_running_get_entry(args->dnode, NULL, true);
		lif = l2vpn_if_find(l2vpn, ifname);
		if (!lif)
			return NB_OK;

		QOBJ_UNREG(lif);
		RB_REMOVE(l2vpn_if_head, &l2vpn->if_tree, lif);
		free(lif);

		if (l2vpn_lib_master.del_hook)
			(*l2vpn_lib_master.del_hook)(l2vpn->name);
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
	struct l2vpn_svc *pw;
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
		l2vpn = nb_running_get_entry(lyd_parent(args->dnode), NULL, true);
		pw = l2vpn_svc_find(l2vpn, ifname);
		if (pw) {
			nb_running_set_entry(args->dnode, pw);
			return NB_OK;
		}
		pw = l2vpn_svc_new(l2vpn, ifname);
		pw->flags = F_PW_STATUSTLV_CONF | F_PW_CWORD_CONF;
		RB_INSERT(l2vpn_svc_head, &l2vpn->svc_inactive_tree, pw);
		QOBJ_REG(pw, l2vpn_svc);

		nb_running_set_entry(args->dnode, pw);

		if (l2vpn_lib_master.event_hook)
			(*l2vpn_lib_master.event_hook)(pw);
		break;
	}

	return NB_OK;
}

static int l2vpn_instance_member_pseudowire_destroy(struct nb_cb_destroy_args *args)
{
	struct l2vpn *l2vpn;
	struct l2vpn_svc *pw;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		l2vpn = nb_running_get_entry(lyd_parent(args->dnode), NULL, true);
		pw = nb_running_unset_entry(args->dnode);
		if (!pw)
			return NB_OK;

		QOBJ_UNREG(pw);
		if (pw->lsr_id.s_addr == INADDR_ANY || pw->pwid == 0)
			RB_REMOVE(l2vpn_svc_head, &l2vpn->svc_inactive_tree, pw);
		else
			RB_REMOVE(l2vpn_svc_head, &l2vpn->svc_tree, pw);

		if (l2vpn_lib_master.event_hook)
			(*l2vpn_lib_master.event_hook)(pw);

		free(pw);
		break;
	}
	return NB_OK;
}

/*
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance/member-pseudowire/neighbor-lsr-id
 */
static int l2vpn_instance_member_pseudowire_neighbor_lsr_id_modify(struct nb_cb_modify_args *args)
{
	struct l2vpn_svc *pw;
	struct ipaddr lsr_id;

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

		if (l2vpn_lib_master.event_hook)
			(*l2vpn_lib_master.event_hook)(pw);
		break;
	}

	return NB_OK;
}

static int l2vpn_instance_member_pseudowire_neighbor_lsr_id_destroy(struct nb_cb_destroy_args *args)
{
	struct l2vpn_svc *pw;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		pw = nb_running_get_entry(args->dnode, NULL, true);
		pw->lsr_id.s_addr = INADDR_ANY;

		if (l2vpn_lib_master.event_hook)
			(*l2vpn_lib_master.event_hook)(pw);
		break;
	}
	return NB_OK;
}

/*
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance/member-pseudowire/pw-id
 */
static int l2vpn_instance_member_pseudowire_pw_id_modify(struct nb_cb_modify_args *args)
{
	uint32_t pw_id;
	struct l2vpn_svc *pw;

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

		if (l2vpn_lib_master.event_hook)
			(*l2vpn_lib_master.event_hook)(pw);
		break;
	}

	return NB_OK;
}

static int l2vpn_instance_member_pseudowire_pw_id_destroy(struct nb_cb_destroy_args *args)
{
	struct l2vpn_svc *pw;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		pw = nb_running_get_entry(args->dnode, NULL, true);
		pw->pwid = 0;

		if (l2vpn_lib_master.event_hook)
			(*l2vpn_lib_master.event_hook)(pw);
		break;
	}
	return NB_OK;
}

/*
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance/member-pseudowire/neighbor-address
 */
static int l2vpn_instance_member_pseudowire_neighbor_address_modify(struct nb_cb_modify_args *args)
{
	struct l2vpn_svc *pw;
	struct ipaddr nbr_id;

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
			pw->addr.ipv4 = nbr_id.ip._v4_addr;
		} else {
			pw->af = AF_INET6;
			IPV6_ADDR_COPY(&pw->addr.ipv6, &nbr_id.ip._v4_addr);
		}
		pw->flags |= F_PW_STATIC_NBR_ADDR;

		if (l2vpn_lib_master.event_hook)
			(*l2vpn_lib_master.event_hook)(pw);
		break;
	}

	return NB_OK;
}

static int l2vpn_instance_member_pseudowire_neighbor_address_destroy(struct nb_cb_destroy_args *args)
{
	struct l2vpn_svc *pw;

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

		if (l2vpn_lib_master.event_hook)
			(*l2vpn_lib_master.event_hook)(pw);
		break;
	}
	return NB_OK;
}

/*
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance/member-pseudowire/control-word
 */
static int l2vpn_instance_member_pseudowire_control_word_modify(struct nb_cb_modify_args *args)
{
	struct l2vpn_svc *pw;

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

		if (l2vpn_lib_master.event_hook)
			(*l2vpn_lib_master.event_hook)(pw);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance/member-pseudowire/pw-status
 */
static int l2vpn_instance_member_pseudowire_pw_status_modify(struct nb_cb_modify_args *args)
{
	struct l2vpn_svc *pw;

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

		if (l2vpn_lib_master.event_hook)
			(*l2vpn_lib_master.event_hook)(pw);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance/member-evpn
 */
static int l2vpn_instance_member_evpn_create(struct nb_cb_create_args *args)
{
	struct l2vpn *l2vpn;
	struct l2vpn_svc *svc;
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
		l2vpn = nb_running_get_entry(lyd_parent(args->dnode), NULL, true);
		svc = l2vpn_svc_find(l2vpn, ifname);
		if (svc) {
			nb_running_set_entry(args->dnode, svc);
			return NB_OK;
		}
		svc = l2vpn_svc_new(l2vpn, ifname);
		RB_INSERT(l2vpn_svc_head, &l2vpn->svc_inactive_tree, svc);
		QOBJ_REG(svc, l2vpn_svc);

		nb_running_set_entry(args->dnode, svc);

		if (l2vpn_lib_master.event_hook)
			(*l2vpn_lib_master.event_hook)(svc);
		break;
	}

	return NB_OK;
}

static int l2vpn_instance_member_evpn_destroy(struct nb_cb_destroy_args *args)
{
	struct l2vpn *l2vpn;
	struct l2vpn_svc *svc;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		l2vpn = nb_running_get_entry(lyd_parent(args->dnode), NULL, true);
		svc = nb_running_unset_entry(args->dnode);
		if (!svc)
			return NB_OK;

		QOBJ_UNREG(svc);
		svc->enabled = false;
		if (l2vpn_lib_master.event_hook)
			(*l2vpn_lib_master.event_hook)(svc);

		RB_REMOVE(l2vpn_svc_head, &l2vpn->svc_inactive_tree, svc);
		free(svc);

		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance/member-evpn/neighbor-evpn
 */
static int l2vpn_instance_member_evpn_neighbor_evpn_modify(struct nb_cb_create_args *args)
{
	struct l2vpn_svc *svc;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		svc = nb_running_get_entry(args->dnode, NULL, true);
		svc->flags |= F_EVPN_NBR_ADDR;

		if (l2vpn_lib_master.event_hook)
			(*l2vpn_lib_master.event_hook)(svc);
		break;
	}

	return NB_OK;
}

static int l2vpn_instance_member_evpn_neighbor_evpn_destroy(struct nb_cb_destroy_args *args)
{
	struct l2vpn_svc *svc;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		svc = nb_running_get_entry(args->dnode, NULL, true);

		svc->enabled = false;
		if (l2vpn_lib_master.event_hook)
			(*l2vpn_lib_master.event_hook)(svc);

		svc->enabled = true;
		svc->flags &= ~F_EVPN_NBR_ADDR;
		svc->local_ac_id = 0;
		svc->remote_ac_id = 0;
		svc->pwid = 0;

		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance/member-evpn/neighbor-evpn/evi
 */
static int l2vpn_instance_member_evpn_neighbor_evpn_evi_modify(struct nb_cb_modify_args *args)
{
	uint32_t evi;
	struct l2vpn *l2vpn;
	struct l2vpn_svc *svc;

	evi = yang_dnode_get_uint32(args->dnode, NULL);
	switch (args->event) {
	case NB_EV_VALIDATE:
		RB_FOREACH (l2vpn, l2vpn_head, &l2vpn_tree_config) {
			if (l2vpn->type != L2VPN_TYPE_VPWS)
				continue;
			RB_FOREACH (svc, l2vpn_svc_head, &l2vpn->svc_tree) {
				if (svc->evi == evi) {
					snprintf(args->errmsg, args->errmsg_len,
						 "%% evi %u already configured", evi);
					return NB_ERR_VALIDATION;
				}
			}
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		svc = nb_running_get_entry(args->dnode, NULL, true);
		if (svc->enabled && svc->evi != evi) {
			svc->enabled = false;
			if (l2vpn_lib_master.event_hook)
				(*l2vpn_lib_master.event_hook)(svc);
			svc->enabled = true;
		}

		svc->evi = evi;
		if (l2vpn_lib_master.event_hook)
			(*l2vpn_lib_master.event_hook)(svc);
		break;
	}

	return NB_OK;
}

static int l2vpn_instance_member_evpn_neighbor_evpn_evi_destroy(struct nb_cb_destroy_args *args)
{
	struct l2vpn_svc *svc;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		svc = nb_running_get_entry(args->dnode, NULL, true);
		svc->enabled = false;
		if (l2vpn_lib_master.event_hook)
			(*l2vpn_lib_master.event_hook)(svc);

		svc->enabled = true;
		svc->pwid = 0;
		break;
	}

	return NB_OK;

}

/*
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance/member-evpn/neighbor-evpn/local-ac-id
 */
static int
l2vpn_instance_member_evpn_neigh_evpn_lc_ac_id_modify(struct nb_cb_modify_args *args)
{
	struct l2vpn_svc *svc;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		svc = nb_running_get_entry(args->dnode, NULL, true);
		svc->local_ac_id = yang_dnode_get_uint32(args->dnode, NULL);
		if (l2vpn_lib_master.event_hook)
			(*l2vpn_lib_master.event_hook)(svc);
		break;
	}

	return NB_OK;
}

static int
l2vpn_instance_member_evpn_neigh_evpn_lc_ac_id_destroy(struct nb_cb_destroy_args *args)
{
	struct l2vpn_svc *svc;

	svc = nb_running_get_entry(args->dnode, NULL, true);
	switch (args->event) {
	case NB_EV_VALIDATE:
		if (svc->local_ac_id != yang_dnode_get_uint32(args->dnode, NULL)) {
			snprintf(args->errmsg, args->errmsg_len, "%% Wrong local-ac-id");
			return NB_ERR_VALIDATION;
		}
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		svc->local_ac_id = 0;
		if (l2vpn_lib_master.event_hook)
			(*l2vpn_lib_master.event_hook)(svc);
		break;
	}
	return NB_OK;
}

/*
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance/member-evpn/neighbor-evpn/remote-ac-id
 */
static int
l2vpn_instance_member_evpn_neigh_evpn_rmt_ac_id_modify(struct nb_cb_modify_args *args)
{
	struct l2vpn_svc *svc;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		svc = nb_running_get_entry(args->dnode, NULL, true);
		svc->remote_ac_id = yang_dnode_get_uint32(args->dnode, NULL);
		if (l2vpn_lib_master.event_hook)
			(*l2vpn_lib_master.event_hook)(svc);
		break;
	}

	return NB_OK;
}

static int
l2vpn_instance_member_evpn_neigh_evpn_rmt_ac_id_destroy(struct nb_cb_destroy_args *args)
{
	struct l2vpn_svc *svc;

	svc = nb_running_get_entry(args->dnode, NULL, true);
	switch (args->event) {
	case NB_EV_VALIDATE:
		if (svc->remote_ac_id != yang_dnode_get_uint32(args->dnode, NULL)) {
			snprintf(args->errmsg, args->errmsg_len, "%% Wrong remote-ac-id");
			return NB_ERR_VALIDATION;
		}
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		svc->remote_ac_id = 0;
		if (l2vpn_lib_master.event_hook)
			(*l2vpn_lib_master.event_hook)(svc);
		break;
	}
	return NB_OK;
}

/*
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance/member-evpn/vni
 */
static int l2vpn_instance_member_evpn_vni_modify(struct nb_cb_modify_args *args)
{
	vni_t vni;
	struct l2vpn_svc *l2vpn_svc;

	vni = yang_dnode_get_uint32(args->dnode, NULL);
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		l2vpn_svc = nb_running_get_entry(args->dnode, NULL, true);
		if (l2vpn_svc->vni && l2vpn_svc->vni != vni) {
			if (l2vpn_lib_master.event_hook) {
				l2vpn_svc->enabled = false;
				(*l2vpn_lib_master.event_hook)(l2vpn_svc);
				l2vpn_svc->enabled = true;
			}
		}

		l2vpn_svc->vni = vni;
		if (l2vpn_lib_master.event_hook)
			(*l2vpn_lib_master.event_hook)(l2vpn_svc);

		break;
	}

	return NB_OK;
}

static int l2vpn_instance_member_evpn_vni_destroy(struct nb_cb_destroy_args *args)
{
	struct l2vpn_svc *l2vpn_svc;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		l2vpn_svc = nb_running_get_entry(args->dnode, NULL, true);
		if (l2vpn_lib_master.event_hook) {
			l2vpn_svc->enabled = false;
			(*l2vpn_lib_master.event_hook)(l2vpn_svc);
			l2vpn_svc->enabled = true;
		}

		l2vpn_svc->vni = 0;
		break;
	}

	return NB_OK;
}

const struct frr_yang_module_info frr_l2vpn = {
	.name = "frr-l2vpn",
	.nodes = {
		{
			.xpath = "/frr-l2vpn:l2vpn/l2vpn-instance",
			.cbs = {
				.create = l2vpn_instance_create,
				.destroy = l2vpn_instance_destroy,
			}
		},
		{
			.xpath = "/frr-l2vpn:l2vpn/l2vpn-instance/pw-type",
			.cbs = {
				.modify = l2vpn_instance_pw_type_modify,
				.destroy = l2vpn_instance_pw_type_destroy,
			}
		},
		{
			.xpath = "/frr-l2vpn:l2vpn/l2vpn-instance/mtu",
			.cbs = {
				.modify = l2vpn_instance_mtu_modify,
				.destroy = l2vpn_instance_mtu_destroy,
			}
		},
		{
			.xpath = "/frr-l2vpn:l2vpn/l2vpn-instance/bridge-interface",
			.cbs = {
				.modify = l2vpn_instance_bridge_interface_modify,
				.destroy = l2vpn_instance_bridge_interface_destroy,
			}
		},
		{
			.xpath = "/frr-l2vpn:l2vpn/l2vpn-instance/member-interface",
			.cbs = {
				.create = l2vpn_instance_member_interface_create,
				.destroy = l2vpn_instance_member_interface_destroy,
			}
		},
		{
			.xpath = "/frr-l2vpn:l2vpn/l2vpn-instance/member-pseudowire",
			.cbs = {
				.create = l2vpn_instance_member_pseudowire_create,
				.destroy = l2vpn_instance_member_pseudowire_destroy,
			}
		},
		{
			.xpath = "/frr-l2vpn:l2vpn/l2vpn-instance/member-pseudowire/neighbor-lsr-id",
			.cbs = {
				.modify = l2vpn_instance_member_pseudowire_neighbor_lsr_id_modify,
				.destroy = l2vpn_instance_member_pseudowire_neighbor_lsr_id_destroy,
			}
		},
		{
			.xpath = "/frr-l2vpn:l2vpn/l2vpn-instance/member-pseudowire/neighbor-address",
			.cbs = {
				.modify = l2vpn_instance_member_pseudowire_neighbor_address_modify,
				.destroy = l2vpn_instance_member_pseudowire_neighbor_address_destroy,
			}
		},
		{
			.xpath = "/frr-l2vpn:l2vpn/l2vpn-instance/member-pseudowire/pw-id",
			.cbs = {
				.modify = l2vpn_instance_member_pseudowire_pw_id_modify,
				.destroy = l2vpn_instance_member_pseudowire_pw_id_destroy,
			}
		},
		{
			.xpath = "/frr-l2vpn:l2vpn/l2vpn-instance/member-pseudowire/control-word",
			.cbs = {
				.modify = l2vpn_instance_member_pseudowire_control_word_modify,
			}
		},
		{
			.xpath = "/frr-l2vpn:l2vpn/l2vpn-instance/member-pseudowire/pw-status",
			.cbs = {
				.modify = l2vpn_instance_member_pseudowire_pw_status_modify,
			}
		},
		{
			.xpath = "/frr-l2vpn:l2vpn/l2vpn-instance/member-evpn",
			.cbs = {
				.create = l2vpn_instance_member_evpn_create,
				.destroy = l2vpn_instance_member_evpn_destroy,
			}
		},
		{
			.xpath = "/frr-l2vpn:l2vpn/l2vpn-instance/member-evpn/neighbor-evpn",
			.cbs = {
				.create = l2vpn_instance_member_evpn_neighbor_evpn_modify,
				.destroy = l2vpn_instance_member_evpn_neighbor_evpn_destroy,
			}
		},
		{
			.xpath = "/frr-l2vpn:l2vpn/l2vpn-instance/member-evpn/neighbor-evpn/evi",
			.cbs = {
				.modify = l2vpn_instance_member_evpn_neighbor_evpn_evi_modify,
				.destroy = l2vpn_instance_member_evpn_neighbor_evpn_evi_destroy,
			}
		},
		{
			.xpath = "/frr-l2vpn:l2vpn/l2vpn-instance/member-evpn/neighbor-evpn/remote-ac-id",
			.cbs = {
				.modify = l2vpn_instance_member_evpn_neigh_evpn_rmt_ac_id_modify,
				.destroy = l2vpn_instance_member_evpn_neigh_evpn_rmt_ac_id_destroy,
			}
		},
		{
			.xpath = "/frr-l2vpn:l2vpn/l2vpn-instance/member-evpn/neighbor-evpn/local-ac-id",
			.cbs = {
				.modify = l2vpn_instance_member_evpn_neigh_evpn_lc_ac_id_modify,
				.destroy = l2vpn_instance_member_evpn_neigh_evpn_lc_ac_id_destroy,
			}
		},
		{
			.xpath = "/frr-l2vpn:l2vpn/l2vpn-instance/member-evpn/vni",
			.cbs = {
				.modify = l2vpn_instance_member_evpn_vni_modify,
				.destroy = l2vpn_instance_member_evpn_vni_destroy,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
