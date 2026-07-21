// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Northbound configuration callbacks
 * Copyright (C) 2026 FRRouting
 */

#include <zebra.h>

#include "northbound.h"
#include "libfrr.h"
#include "defaults.h"
#include "vrf.h"
#include "prefix.h"
#include "lib_errors.h"
#include "routing_nb.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_nb.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_mplsvpn.h"

/*
 * XPath: .../frr-bgp:bgp
 */
int bgp_nb_bgp_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp = NULL;
	const char *vrf_name;
	const char *name;
	enum bgp_instance_type inst_type;
	as_t as;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf_name = yang_dnode_get_string(args->dnode, "../vrf");
		as = yang_dnode_get_uint32(args->dnode, "./global/local-as");

		if (strmatch(vrf_name, VRF_DEFAULT_NAME)) {
			name = NULL;
			inst_type = BGP_INSTANCE_TYPE_DEFAULT;
		} else if (yang_dnode_exists(args->dnode, "./global/instance-type-view") &&
			   yang_dnode_get_bool(args->dnode, "./global/instance-type-view")) {
			name = vrf_name;
			inst_type = BGP_INSTANCE_TYPE_VIEW;
		} else {
			name = vrf_name;
			inst_type = BGP_INSTANCE_TYPE_VRF;
		}

		ret = bgp_get(&bgp, &as, name, inst_type, NULL, ASNOTATION_PLAIN);
		if (ret != BGP_SUCCESS && ret != BGP_CREATED && ret != BGP_INSTANCE_EXISTS)
			return NB_ERR_RESOURCE;

		if (inst_type == BGP_INSTANCE_TYPE_VRF || IS_BGP_INSTANCE_HIDDEN(bgp)) {
			bgp_vpn_leak_export(bgp);
			UNSET_FLAG(bgp->vrf_flags, BGP_VRF_AUTO);
			UNSET_FLAG(bgp->flags, BGP_FLAG_INSTANCE_HIDDEN);
			UNSET_FLAG(bgp->flags, BGP_FLAG_DELETE_IN_PROGRESS);
		}

		nb_running_set_entry(args->dnode, bgp);
		bgp_vpn_leak_export(bgp);
		break;
	}

	return NB_OK;
}

int bgp_nb_bgp_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const char *vrf_name;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, false);
	if (bgp) {
		nb_running_unset_entry(args->dnode);
	} else {
		vrf_name = yang_dnode_get_string(args->dnode, "../vrf");
		if (strmatch(vrf_name, VRF_DEFAULT_NAME))
			bgp = bgp_get_default();
		else
			bgp = bgp_lookup_by_name(vrf_name);
		if (!bgp)
			return NB_OK;
	}

	bgp_delete(bgp);
	return NB_OK;
}

int bgp_nb_routing_destroy(struct nb_cb_destroy_args *args)
{
	struct lyd_node *bgp_dnode;
	struct nb_cb_destroy_args destroy_args;
	const char *type;

	type = yang_dnode_get_string(args->dnode, "type");
	if (!type || !strmatch(type, "frr-bgp:bgp"))
		return NB_OK;

	bgp_dnode = yang_dnode_get(args->dnode, "frr-bgp:bgp");
	if (!bgp_dnode)
		return NB_OK;

	memset(&destroy_args, 0, sizeof(destroy_args));
	destroy_args.dnode = bgp_dnode;
	destroy_args.event = args->event;
	return bgp_nb_bgp_destroy(&destroy_args);
}

void bgp_nb_cli_show_router_bgp(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const struct lyd_node *cpp;
	const char *vrf_name;
	const char *name;
	as_t as;
	bool is_view = false;

	cpp = yang_dnode_get_parent(dnode, "control-plane-protocol");
	vrf_name = yang_dnode_get_string(cpp, "vrf");
	name = yang_dnode_get_string(cpp, "name");
	as = yang_dnode_get_uint32(dnode, "./global/local-as");

	if (yang_dnode_exists(dnode, "./global/instance-type-view"))
		is_view = yang_dnode_get_bool(dnode, "./global/instance-type-view");

	vty_out(vty, "!\n");
	vty_out(vty, "router bgp %u", as);
	if (is_view)
		vty_out(vty, " view %s", name);
	else if (!strmatch(vrf_name, VRF_DEFAULT_NAME))
		vty_out(vty, " vrf %s", vrf_name);
	vty_out(vty, "\n");
}

void bgp_nb_cli_show_router_bgp_end(struct vty *vty, const struct lyd_node *dnode)
{
	vty_out(vty, "exit\n");
}

/*
 * XPath: .../global/local-as
 */
int bgp_nb_local_as_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	as_t new_as, old_as;
	struct peer *peer;
	struct listnode *node;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	new_as = yang_dnode_get_uint32(args->dnode, NULL);
	old_as = bgp->as;
	if (old_as == new_as)
		return NB_OK;

	bgp->as = new_as;
	for (ALL_LIST_ELEMENTS_RO(bgp->peer, node, peer)) {
		if (peer->local_as == old_as)
			peer->local_as = new_as;
	}

	return NB_OK;
}

/*
 * XPath: .../global/router-id
 */
int bgp_nb_router_id_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct in_addr router_id;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (inet_pton(AF_INET, yang_dnode_get_string(args->dnode, NULL), &router_id) != 1)
		return NB_ERR_VALIDATION;
	bgp_router_id_static_set(bgp, router_id);
	return NB_OK;
}

int bgp_nb_router_id_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	struct in_addr router_id = {};

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp_router_id_static_set(bgp, router_id);
	return NB_OK;
}

void bgp_nb_cli_show_router_id(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, " bgp router-id %s\n", yang_dnode_get_string(dnode, NULL));
}

int bgp_nb_instance_type_view_modify(struct nb_cb_modify_args *args)
{
	/* Applied at create time via bgp_nb_bgp_create; nothing further. */
	return NB_OK;
}

int bgp_nb_as_notation_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *notation;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	notation = yang_dnode_get_string(args->dnode, NULL);
	if (strmatch(notation, "dot+"))
		bgp->asnotation = ASNOTATION_DOTPLUS;
	else if (strmatch(notation, "dot"))
		bgp->asnotation = ASNOTATION_DOT;
	else
		bgp->asnotation = ASNOTATION_PLAIN;
	return NB_OK;
}

int bgp_nb_log_neighbor_changes_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_LOG_NEIGHBOR_CHANGES);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_LOG_NEIGHBOR_CHANGES);
	return NB_OK;
}

void bgp_nb_cli_show_log_neighbor_changes(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults)
{
	bool enabled = yang_dnode_get_bool(dnode, NULL);
	bool profile_on = (frr_default_chosen() == FRR_DEFAULT_DATACENTER);

	/*
	 * Match classic config write: keep the line only when it differs
	 * from the active defaults profile, so "no bgp log-neighbor-changes"
	 * survives a save under datacenter.
	 */
	if (!show_defaults && enabled == profile_on)
		return;
	vty_out(vty, " %sbgp log-neighbor-changes\n", enabled ? "" : "no ");
}

int bgp_nb_ebgp_requires_policy_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_EBGP_REQUIRES_POLICY);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_EBGP_REQUIRES_POLICY);
	return NB_OK;
}

void bgp_nb_cli_show_ebgp_requires_policy(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults)
{
	bool enabled = yang_dnode_get_bool(dnode, NULL);

	if (enabled)
		vty_out(vty, " bgp ebgp-requires-policy\n");
	else
		vty_out(vty, " no bgp ebgp-requires-policy\n");
}

int bgp_nb_import_check_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (yang_dnode_get_bool(args->dnode, NULL)) {
		if (CHECK_FLAG(bgp->flags, BGP_FLAG_IMPORT_CHECK))
			return NB_OK;
		SET_FLAG(bgp->flags, BGP_FLAG_IMPORT_CHECK);
	} else {
		if (!CHECK_FLAG(bgp->flags, BGP_FLAG_IMPORT_CHECK))
			return NB_OK;
		UNSET_FLAG(bgp->flags, BGP_FLAG_IMPORT_CHECK);
	}
	bgp_static_redo_import_check(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_import_check(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	bool enabled = yang_dnode_get_bool(dnode, NULL);

	if (enabled)
		vty_out(vty, " bgp network import-check\n");
	else
		vty_out(vty, " no bgp network import-check\n");
}
