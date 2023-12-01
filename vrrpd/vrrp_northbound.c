// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * VRRP northbound bindings.
 * Copyright (C) 2019  Cumulus Networks, Inc.
 * Quentin Young
 */

#include <zebra.h>

#include "if.h"
#include "log.h"
#include "prefix.h"
#include "table.h"
#include "command.h"
#include "northbound.h"
#include "libfrr.h"
#include "vrrp.h"
#include "vrrp_vty.h"

/*
 * XPath: /frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group
 */
static int lib_interface_vrrp_vrrp_group_create(struct nb_cb_create_args *args)
{
	struct interface *ifp;
	uint8_t vrid;
	uint8_t version = 3;
	struct vrrp_vrouter *vr;

	vrid = yang_dnode_get_uint8(args->dnode, "virtual-router-id");
	version = yang_dnode_get_enum(args->dnode, "version");

	switch (args->event) {
	case NB_EV_VALIDATE:
		ifp = nb_running_get_entry(args->dnode, NULL, false);
		if (ifp) {
			vr = vrrp_lookup(ifp, vrid);
			if (vr && vr->autoconf) {
				snprintf(
					args->errmsg, args->errmsg_len,
					"Virtual Router with ID %d already exists on interface '%s'; created by VRRP autoconfiguration",
					vrid, ifp->name);
				return NB_ERR_VALIDATION;
			}
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	vr = vrrp_vrouter_create(ifp, vrid, version);
	nb_running_set_entry(args->dnode, vr);

	return NB_OK;
}

static int
lib_interface_vrrp_vrrp_group_destroy(struct nb_cb_destroy_args *args)
{
	struct vrrp_vrouter *vr;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	vr = nb_running_unset_entry(args->dnode);
	vrrp_vrouter_destroy(vr);

	return NB_OK;
}

static const void *
lib_interface_vrrp_vrrp_group_get_next(struct nb_cb_get_next_args *args)
{
	struct list *l = hash_to_list(vrrp_vrouters_hash);
	struct listnode *ln;
	const struct vrrp_vrouter *curr;
	const struct interface *ifp = args->parent_list_entry;

	/*
	 * If list_entry is null, we return the first vrrp instance with a
	 * matching interface
	 */
	bool nextone = args->list_entry ? false : true;

	for (ALL_LIST_ELEMENTS_RO(l, ln, curr)) {
		if (curr == args->list_entry) {
			nextone = true;
			continue;
		}

		if (nextone && curr->ifp == ifp)
			goto done;
	}

	curr = NULL;

done:
	list_delete(&l);
	return curr;
}

static int
lib_interface_vrrp_vrrp_group_get_keys(struct nb_cb_get_keys_args *args)
{
	const struct vrrp_vrouter *vr = args->list_entry;

	args->keys->num = 1;
	snprintf(args->keys->key[0], sizeof(args->keys->key[0]), "%u",
		 vr->vrid);

	return NB_OK;
}

static const void *
lib_interface_vrrp_vrrp_group_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	uint32_t vrid = strtoul(args->keys->key[0], NULL, 10);
	const struct interface *ifp = args->parent_list_entry;

	return vrrp_lookup(ifp, vrid);
}

/*
 * XPath: /frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/version
 */
static int
lib_interface_vrrp_vrrp_group_version_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	struct vrrp_vrouter *vr;
	uint8_t version;

	vr = nb_running_get_entry(args->dnode, NULL, true);
	vrrp_event(vr->v4, VRRP_EVENT_SHUTDOWN);
	vrrp_event(vr->v6, VRRP_EVENT_SHUTDOWN);
	version = yang_dnode_get_enum(args->dnode, NULL);
	vr->version = version;

	vrrp_check_start(vr);

	return NB_OK;
}

/*
 * Helper function for address list OP_MODIFY callbacks.
 */
static void vrrp_yang_add_del_virtual_address(const struct lyd_node *dnode,
					      bool add)
{
	struct vrrp_vrouter *vr;
	struct ipaddr ip;

	vr = nb_running_get_entry(dnode, NULL, true);
	yang_dnode_get_ip(&ip, dnode, NULL);
	if (add)
		vrrp_add_ip(vr, &ip);
	else
		vrrp_del_ip(vr, &ip);

	vrrp_check_start(vr);
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/v4/virtual-address
 */
static int lib_interface_vrrp_vrrp_group_v4_virtual_address_create(
	struct nb_cb_create_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	vrrp_yang_add_del_virtual_address(args->dnode, true);

	return NB_OK;
}

static int lib_interface_vrrp_vrrp_group_v4_virtual_address_destroy(
	struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	vrrp_yang_add_del_virtual_address(args->dnode, false);

	return NB_OK;
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/v4/current-priority
 */
static struct yang_data *
lib_interface_vrrp_vrrp_group_v4_current_priority_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct vrrp_vrouter *vr = args->list_entry;

	return yang_data_new_uint8(args->xpath, vr->v4->priority);
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/v4/vrrp-interface
 */
static struct yang_data *
lib_interface_vrrp_vrrp_group_v4_vrrp_interface_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct vrrp_vrouter *vr = args->list_entry;

	struct yang_data *val = NULL;

	if (vr->v4->mvl_ifp)
		val = yang_data_new_string(args->xpath, vr->v4->mvl_ifp->name);

	return val;
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/v4/source-address
 */
static struct yang_data *
lib_interface_vrrp_vrrp_group_v4_source_address_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct vrrp_vrouter *vr = args->list_entry;
	struct yang_data *val = NULL;

	if (!ipaddr_is_zero(&vr->v4->src))
		val = yang_data_new_ip(args->xpath, &vr->v4->src);

	return val;
}

/*
 * XPath: /frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/v4/state
 */
static struct yang_data *lib_interface_vrrp_vrrp_group_v4_state_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct vrrp_vrouter *vr = args->list_entry;

	return yang_data_new_enum(args->xpath, vr->v4->fsm.state);
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/v4/master-advertisement-interval
 */
static struct yang_data *
lib_interface_vrrp_vrrp_group_v4_master_advertisement_interval_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct vrrp_vrouter *vr = args->list_entry;

	return yang_data_new_uint16(args->xpath, vr->v4->master_adver_interval);
}

/*
 * XPath: /frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/v4/skew-time
 */
static struct yang_data *lib_interface_vrrp_vrrp_group_v4_skew_time_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct vrrp_vrouter *vr = args->list_entry;

	return yang_data_new_uint16(args->xpath, vr->v4->skew_time);
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/v4/counter/state-transition
 */
static struct yang_data *
lib_interface_vrrp_vrrp_group_v4_counter_state_transition_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct vrrp_vrouter *vr = args->list_entry;

	return yang_data_new_uint32(args->xpath, vr->v4->stats.trans_cnt);
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/v4/counter/tx/advertisement
 */
static struct yang_data *
lib_interface_vrrp_vrrp_group_v4_counter_tx_advertisement_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct vrrp_vrouter *vr = args->list_entry;

	return yang_data_new_uint32(args->xpath, vr->v4->stats.adver_tx_cnt);
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/v4/counter/tx/gratuitous-arp
 */
static struct yang_data *
lib_interface_vrrp_vrrp_group_v4_counter_tx_gratuitous_arp_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct vrrp_vrouter *vr = args->list_entry;

	return yang_data_new_uint32(args->xpath, vr->v4->stats.garp_tx_cnt);
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/v4/counter/rx/advertisement
 */
static struct yang_data *
lib_interface_vrrp_vrrp_group_v4_counter_rx_advertisement_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct vrrp_vrouter *vr = args->list_entry;

	return yang_data_new_uint32(args->xpath, vr->v4->stats.adver_rx_cnt);
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/v6/virtual-address
 */
static int lib_interface_vrrp_vrrp_group_v6_virtual_address_create(
	struct nb_cb_create_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	vrrp_yang_add_del_virtual_address(args->dnode, true);

	return NB_OK;
}

static int lib_interface_vrrp_vrrp_group_v6_virtual_address_destroy(
	struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	vrrp_yang_add_del_virtual_address(args->dnode, false);

	return NB_OK;
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/v6/current-priority
 */
static struct yang_data *
lib_interface_vrrp_vrrp_group_v6_current_priority_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct vrrp_vrouter *vr = args->list_entry;

	return yang_data_new_uint8(args->xpath, vr->v6->priority);
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/v6/vrrp-interface
 */
static struct yang_data *
lib_interface_vrrp_vrrp_group_v6_vrrp_interface_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct vrrp_vrouter *vr = args->list_entry;
	struct yang_data *val = NULL;

	if (vr->v6->mvl_ifp)
		val = yang_data_new_string(args->xpath, vr->v6->mvl_ifp->name);

	return val;
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/v6/source-address
 */
static struct yang_data *
lib_interface_vrrp_vrrp_group_v6_source_address_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct vrrp_vrouter *vr = args->list_entry;
	struct yang_data *val = NULL;

	if (!ipaddr_is_zero(&vr->v6->src))
		val = yang_data_new_ip(args->xpath, &vr->v6->src);

	return val;
}

/*
 * XPath: /frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/v6/state
 */
static struct yang_data *lib_interface_vrrp_vrrp_group_v6_state_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct vrrp_vrouter *vr = args->list_entry;

	return yang_data_new_enum(args->xpath, vr->v6->fsm.state);
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/v6/master-advertisement-interval
 */
static struct yang_data *
lib_interface_vrrp_vrrp_group_v6_master_advertisement_interval_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct vrrp_vrouter *vr = args->list_entry;

	return yang_data_new_uint16(args->xpath, vr->v6->master_adver_interval);
}

/*
 * XPath: /frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/v6/skew-time
 */
static struct yang_data *lib_interface_vrrp_vrrp_group_v6_skew_time_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct vrrp_vrouter *vr = args->list_entry;

	return yang_data_new_uint16(args->xpath, vr->v6->skew_time);
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/v6/counter/state-transition
 */
static struct yang_data *
lib_interface_vrrp_vrrp_group_v6_counter_state_transition_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct vrrp_vrouter *vr = args->list_entry;

	return yang_data_new_uint32(args->xpath, vr->v6->stats.trans_cnt);
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/v6/counter/tx/advertisement
 */
static struct yang_data *
lib_interface_vrrp_vrrp_group_v6_counter_tx_advertisement_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct vrrp_vrouter *vr = args->list_entry;

	return yang_data_new_uint32(args->xpath, vr->v6->stats.adver_tx_cnt);
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/v6/counter/tx/neighbor-advertisement
 */
static struct yang_data *
lib_interface_vrrp_vrrp_group_v6_counter_tx_neighbor_advertisement_get_elem(
	struct nb_cb_get_elem_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/v6/counter/rx/advertisement
 */
static struct yang_data *
lib_interface_vrrp_vrrp_group_v6_counter_rx_advertisement_get_elem(
	struct nb_cb_get_elem_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/priority
 */
static int
lib_interface_vrrp_vrrp_group_priority_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	struct vrrp_vrouter *vr;
	uint8_t priority;

	vr = nb_running_get_entry(args->dnode, NULL, true);
	priority = yang_dnode_get_uint8(args->dnode, NULL);
	vrrp_set_priority(vr, priority);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/preempt
 */
static int
lib_interface_vrrp_vrrp_group_preempt_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	struct vrrp_vrouter *vr;
	bool preempt;

	vr = nb_running_get_entry(args->dnode, NULL, true);
	preempt = yang_dnode_get_bool(args->dnode, NULL);
	vr->preempt_mode = preempt;

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/accept-mode
 */
static int
lib_interface_vrrp_vrrp_group_accept_mode_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	struct vrrp_vrouter *vr;
	bool accept;

	vr = nb_running_get_entry(args->dnode, NULL, true);
	accept = yang_dnode_get_bool(args->dnode, NULL);
	vr->accept_mode = accept;

	return NB_OK;
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/advertisement-interval
 */
static int lib_interface_vrrp_vrrp_group_advertisement_interval_modify(
	struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	struct vrrp_vrouter *vr;
	uint16_t advert_int;

	vr = nb_running_get_entry(args->dnode, NULL, true);
	advert_int = yang_dnode_get_uint16(args->dnode, NULL);
	vrrp_set_advertisement_interval(vr, advert_int);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/shutdown
 */
static int
lib_interface_vrrp_vrrp_group_shutdown_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	struct vrrp_vrouter *vr;
	bool shutdown;

	vr = nb_running_get_entry(args->dnode, NULL, true);
	shutdown = yang_dnode_get_bool(args->dnode, NULL);

	vr->shutdown = shutdown;

	if (shutdown) {
		vrrp_event(vr->v4, VRRP_EVENT_SHUTDOWN);
		vrrp_event(vr->v6, VRRP_EVENT_SHUTDOWN);
	} else {
		vrrp_check_start(vr);
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/checksum-with-
 *        ipv4-pseudoheader
 */
static int lib_interface_vrrp_vrrp_group_checksum_with_ipv4_pseudoheader_modify(
	struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	struct vrrp_vrouter *vr;
	bool checksum_with_ipv4_ph;

	vr = nb_running_get_entry(args->dnode, NULL, true);
	checksum_with_ipv4_ph = yang_dnode_get_bool(args->dnode, NULL);
	vr->checksum_with_ipv4_pseudoheader = checksum_with_ipv4_ph;

	return NB_OK;
}

/* clang-format off */
const struct frr_yang_module_info frr_vrrpd_info = {
	.name = "frr-vrrpd",
	.nodes = {
		{
			.xpath = "/frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group",
			.cbs = {
				.create = lib_interface_vrrp_vrrp_group_create,
				.destroy = lib_interface_vrrp_vrrp_group_destroy,
				.get_next = lib_interface_vrrp_vrrp_group_get_next,
				.get_keys = lib_interface_vrrp_vrrp_group_get_keys,
				.lookup_entry = lib_interface_vrrp_vrrp_group_lookup_entry,
				.cli_show = cli_show_vrrp,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/version",
			.cbs = {
				.modify = lib_interface_vrrp_vrrp_group_version_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/priority",
			.cbs = {
				.modify = lib_interface_vrrp_vrrp_group_priority_modify,
				.cli_show = cli_show_priority,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/preempt",
			.cbs = {
				.modify = lib_interface_vrrp_vrrp_group_preempt_modify,
				.cli_show = cli_show_preempt,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/accept-mode",
			.cbs = {
				.modify = lib_interface_vrrp_vrrp_group_accept_mode_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/checksum-with-ipv4-pseudoheader",
			.cbs = {
				.modify = lib_interface_vrrp_vrrp_group_checksum_with_ipv4_pseudoheader_modify,
				.cli_show = cli_show_checksum_with_ipv4_pseudoheader,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/advertisement-interval",
			.cbs = {
				.modify = lib_interface_vrrp_vrrp_group_advertisement_interval_modify,
				.cli_show = cli_show_advertisement_interval,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/shutdown",
			.cbs = {
				.modify = lib_interface_vrrp_vrrp_group_shutdown_modify,
				.cli_show = cli_show_shutdown,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/v4/virtual-address",
			.cbs = {
				.create = lib_interface_vrrp_vrrp_group_v4_virtual_address_create,
				.destroy = lib_interface_vrrp_vrrp_group_v4_virtual_address_destroy,
				.cli_show = cli_show_ip,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/v4/current-priority",
			.cbs = {
				.get_elem = lib_interface_vrrp_vrrp_group_v4_current_priority_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/v4/vrrp-interface",
			.cbs = {
				.get_elem = lib_interface_vrrp_vrrp_group_v4_vrrp_interface_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/v4/source-address",
			.cbs = {
				.get_elem = lib_interface_vrrp_vrrp_group_v4_source_address_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/v4/state",
			.cbs = {
				.get_elem = lib_interface_vrrp_vrrp_group_v4_state_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/v4/master-advertisement-interval",
			.cbs = {
				.get_elem = lib_interface_vrrp_vrrp_group_v4_master_advertisement_interval_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/v4/skew-time",
			.cbs = {
				.get_elem = lib_interface_vrrp_vrrp_group_v4_skew_time_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/v4/counter/state-transition",
			.cbs = {
				.get_elem = lib_interface_vrrp_vrrp_group_v4_counter_state_transition_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/v4/counter/tx/advertisement",
			.cbs = {
				.get_elem = lib_interface_vrrp_vrrp_group_v4_counter_tx_advertisement_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/v4/counter/tx/gratuitous-arp",
			.cbs = {
				.get_elem = lib_interface_vrrp_vrrp_group_v4_counter_tx_gratuitous_arp_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/v4/counter/rx/advertisement",
			.cbs = {
				.get_elem = lib_interface_vrrp_vrrp_group_v4_counter_rx_advertisement_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/v6/virtual-address",
			.cbs = {
				.create = lib_interface_vrrp_vrrp_group_v6_virtual_address_create,
				.destroy = lib_interface_vrrp_vrrp_group_v6_virtual_address_destroy,
				.cli_show = cli_show_ipv6,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/v6/current-priority",
			.cbs = {
				.get_elem = lib_interface_vrrp_vrrp_group_v6_current_priority_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/v6/vrrp-interface",
			.cbs = {
				.get_elem = lib_interface_vrrp_vrrp_group_v6_vrrp_interface_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/v6/source-address",
			.cbs = {
				.get_elem = lib_interface_vrrp_vrrp_group_v6_source_address_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/v6/state",
			.cbs = {
				.get_elem = lib_interface_vrrp_vrrp_group_v6_state_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/v6/master-advertisement-interval",
			.cbs = {
				.get_elem = lib_interface_vrrp_vrrp_group_v6_master_advertisement_interval_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/v6/skew-time",
			.cbs = {
				.get_elem = lib_interface_vrrp_vrrp_group_v6_skew_time_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/v6/counter/state-transition",
			.cbs = {
				.get_elem = lib_interface_vrrp_vrrp_group_v6_counter_state_transition_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/v6/counter/tx/advertisement",
			.cbs = {
				.get_elem = lib_interface_vrrp_vrrp_group_v6_counter_tx_advertisement_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/v6/counter/tx/neighbor-advertisement",
			.cbs = {
				.get_elem = lib_interface_vrrp_vrrp_group_v6_counter_tx_neighbor_advertisement_get_elem,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-vrrpd:vrrp/vrrp-group/v6/counter/rx/advertisement",
			.cbs = {
				.get_elem = lib_interface_vrrp_vrrp_group_v6_counter_rx_advertisement_get_elem,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
