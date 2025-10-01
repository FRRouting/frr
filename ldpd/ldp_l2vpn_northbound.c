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
#include "ldp_l2vpn.h"

/*
 * XPath: /frr-ldp-l2vpn:l2vpn/l2vpn-instance
 */
static int ldp_l2vpn_instance_create(struct nb_cb_create_args *args)
{
	return NB_OK;
}

static int ldp_l2vpn_instance_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

/*
 * XPath: /frr-ldp-l2vpn:l2vpn/l2vpn-instance/pw-type
 */
static int ldp_l2vpn_instance_pw_type_modify(struct nb_cb_modify_args *args)
{
	return NB_OK;
}

static int ldp_l2vpn_instance_pw_type_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

/*
 * XPath: /frr-ldp-l2vpn:l2vpn/l2vpn-instance/mtu
 */
static int ldp_l2vpn_instance_mtu_modify(struct nb_cb_modify_args *args)
{
	return NB_OK;
}

static int ldp_l2vpn_instance_mtu_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

/*
 * XPath: /frr-ldp-l2vpn:l2vpn/l2vpn-instance/bridge-interface
 */
static int ldp_l2vpn_instance_bridge_interface_modify(struct nb_cb_modify_args *args)
{
	return NB_OK;
}

static int ldp_l2vpn_instance_bridge_interface_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

/*
 * XPath: /frr-ldp-l2vpn:l2vpn/l2vpn-instance/member-interface
 */
static int ldp_l2vpn_instance_member_interface_create(struct nb_cb_create_args *args)
{
	return NB_OK;
}

static int ldp_l2vpn_instance_member_interface_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

/*
 * XPath: /frr-ldp-l2vpn:l2vpn/l2vpn-instance/member-pseudowire
 */
static int ldp_l2vpn_instance_member_pseudowire_create(struct nb_cb_create_args *args)
{
	return NB_OK;
}

static int ldp_l2vpn_instance_member_pseudowire_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

/*
 * XPath: /frr-ldp-l2vpn:l2vpn/l2vpn-instance/member-pseudowire/neighbor-lsr-id
 */
static int
ldp_l2vpn_instance_member_pseudowire_neighbor_lsr_id_modify(struct nb_cb_modify_args *args)
{
	return NB_OK;
}

static int
ldp_l2vpn_instance_member_pseudowire_neighbor_lsr_id_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

/*
 * XPath: /frr-ldp-l2vpn:l2vpn/l2vpn-instance/member-pseudowire/pw-id
 */
static int ldp_l2vpn_instance_member_pseudowire_pw_id_modify(struct nb_cb_modify_args *args)
{
	return NB_OK;
}

static int ldp_l2vpn_instance_member_pseudowire_pw_id_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

/*
 * XPath: /frr-ldp-l2vpn:l2vpn/l2vpn-instance/member-pseudowire/neighbor-address
 */
static int
ldp_l2vpn_instance_member_pseudowire_neighbor_address_modify(struct nb_cb_modify_args *args)
{
	return NB_OK;
}

static int
ldp_l2vpn_instance_member_pseudowire_neighbor_address_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

/*
 * XPath: /frr-ldp-l2vpn:l2vpn/l2vpn-instance/member-pseudowire/control-word
 */
static int ldp_l2vpn_instance_member_pseudowire_control_word_modify(struct nb_cb_modify_args *args)
{
	return NB_OK;
}

/*
 * XPath: /frr-ldp-l2vpn:l2vpn/l2vpn-instance/member-pseudowire/pw-status
 */
static int ldp_l2vpn_instance_member_pseudowire_pw_status_modify(struct nb_cb_modify_args *args)
{
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
