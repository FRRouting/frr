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
#include "bgpd/bgp_open.h"
#include "bgpd/bgp_nb.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_addpath.h"
#include "bgpd/bgp_updgrp.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_io.h"
#include "bgpd/bgp_updgrp.h"

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

int bgp_nb_cluster_id_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct in_addr cluster;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (!inet_aton(yang_dnode_get_string(args->dnode, NULL), &cluster)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "Malformed bgp cluster identifier");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	inet_aton(yang_dnode_get_string(args->dnode, NULL), &cluster);
	bgp_cluster_id_set(bgp, &cluster);
	bgp_clear_all_soft_out(bgp);
	return NB_OK;
}

int bgp_nb_cluster_id_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp_cluster_id_unset(bgp);
	bgp_clear_all_soft_out(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_cluster_id(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, " bgp cluster-id %s\n", yang_dnode_get_string(dnode, NULL));
}

int bgp_nb_no_client_reflect_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_NO_CLIENT_TO_CLIENT);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_NO_CLIENT_TO_CLIENT);
	bgp_clear_all_soft_out(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_no_client_reflect(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no bgp client-to-client reflection\n");
	else if (show_defaults)
		vty_out(vty, " bgp client-to-client reflection\n");
}

int bgp_nb_always_compare_med_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_ALWAYS_COMPARE_MED);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_ALWAYS_COMPARE_MED);
	bgp_recalculate_all_bestpaths(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_always_compare_med(struct vty *vty, const struct lyd_node *dnode,
					bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp always-compare-med\n");
	else if (show_defaults)
		vty_out(vty, " no bgp always-compare-med\n");
}

int bgp_nb_deterministic_med_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct peer *peer;
	struct listnode *node, *nnode;
	afi_t afi;
	safi_t safi;
	bool enable;

	enable = yang_dnode_get_bool(args->dnode, NULL);

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (enable)
			return NB_OK;
		bgp = nb_running_get_entry(args->dnode, NULL, false);
		if (!bgp)
			return NB_OK;
		if (!CHECK_FLAG(bgp->flags, BGP_FLAG_DETERMINISTIC_MED))
			return NB_OK;
		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
			FOREACH_AFI_SAFI (afi, safi) {
				if (bgp_addpath_dmed_required(peer->addpath_type[afi][safi])) {
					snprintfrr(args->errmsg, args->errmsg_len,
						   "bgp deterministic-med cannot be disabled while addpath-tx-bestpath-per-AS is in use");
					return NB_ERR_VALIDATION;
				}
			}
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (enable) {
		if (!CHECK_FLAG(bgp->flags, BGP_FLAG_DETERMINISTIC_MED)) {
			SET_FLAG(bgp->flags, BGP_FLAG_DETERMINISTIC_MED);
			bgp_recalculate_all_bestpaths(bgp);
		}
	} else if (CHECK_FLAG(bgp->flags, BGP_FLAG_DETERMINISTIC_MED)) {
		UNSET_FLAG(bgp->flags, BGP_FLAG_DETERMINISTIC_MED);
		bgp_recalculate_all_bestpaths(bgp);
	}
	return NB_OK;
}

void bgp_nb_cli_show_deterministic_med(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp deterministic-med\n");
	else if (show_defaults)
		vty_out(vty, " no bgp deterministic-med\n");
}

int bgp_nb_local_pref_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp_default_local_preference_set(bgp, yang_dnode_get_uint32(args->dnode, NULL));
	bgp_clear_all_soft_in(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_local_pref(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	uint32_t pref = yang_dnode_get_uint32(dnode, NULL);

	if (pref != 100 || show_defaults)
		vty_out(vty, " bgp default local-preference %u\n", pref);
}

int bgp_nb_fast_external_failover_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	bool enabled;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	/* YANG true => feature enabled => clear NO_FAST flag */
	enabled = yang_dnode_get_bool(args->dnode, NULL);
	if (enabled)
		UNSET_FLAG(bgp->flags, BGP_FLAG_NO_FAST_EXT_FAILOVER);
	else
		SET_FLAG(bgp->flags, BGP_FLAG_NO_FAST_EXT_FAILOVER);
	return NB_OK;
}

void bgp_nb_cli_show_fast_external_failover(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no bgp fast-external-failover\n");
	else if (show_defaults)
		vty_out(vty, " bgp fast-external-failover\n");
}

int bgp_nb_suppress_duplicates_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_SUPPRESS_DUPLICATES);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_SUPPRESS_DUPLICATES);
	return NB_OK;
}

void bgp_nb_cli_show_suppress_duplicates(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL)) {
		if (show_defaults)
			vty_out(vty, " bgp suppress-duplicates\n");
	} else
		vty_out(vty, " no bgp suppress-duplicates\n");
}

int bgp_nb_graceful_shutdown_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	bool enable;

	enable = yang_dnode_get_bool(args->dnode, NULL);

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (CHECK_FLAG(bm->flags, BM_FLAG_GRACEFUL_SHUTDOWN)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "per-vrf graceful-shutdown not permitted with global graceful-shutdown");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (enable) {
		if (!CHECK_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_SHUTDOWN)) {
			SET_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_SHUTDOWN);
			bgp_initiate_graceful_shut_unshut(bgp);
		}
	} else if (CHECK_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_SHUTDOWN)) {
		UNSET_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_SHUTDOWN);
		bgp_initiate_graceful_shut_unshut(bgp);
	}
	return NB_OK;
}

void bgp_nb_cli_show_graceful_shutdown(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp graceful-shutdown\n");
	else if (show_defaults)
		vty_out(vty, " no bgp graceful-shutdown\n");
}

int bgp_nb_reject_as_sets_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct listnode *node, *nnode;
	struct peer *peer;
	bool reject;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	reject = yang_dnode_get_bool(args->dnode, NULL);
	if (bgp->reject_as_sets == reject)
		return NB_OK;

	bgp->reject_as_sets = reject;
	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
		peer_set_last_reset(peer, PEER_DOWN_AS_SETS_REJECT);
		peer_notify_config_change(peer->connection);
	}
	return NB_OK;
}

void bgp_nb_cli_show_reject_as_sets(struct vty *vty, const struct lyd_node *dnode,
				    bool show_defaults)
{
	/* Default is true; only emit "no" when disabled. */
	if (yang_dnode_get_bool(dnode, NULL)) {
		if (show_defaults)
			vty_out(vty, " bgp reject-as-sets\n");
	} else
		vty_out(vty, " no bgp reject-as-sets\n");
}

int bgp_nb_enforce_first_as_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct listnode *node;
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	bool enable;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	enable = yang_dnode_get_bool(args->dnode, NULL);
	if (enable) {
		if (CHECK_FLAG(bgp->flags, BGP_FLAG_ENFORCE_FIRST_AS))
			return NB_OK;
		SET_FLAG(bgp->flags, BGP_FLAG_ENFORCE_FIRST_AS);
	} else {
		if (!CHECK_FLAG(bgp->flags, BGP_FLAG_ENFORCE_FIRST_AS))
			return NB_OK;
		UNSET_FLAG(bgp->flags, BGP_FLAG_ENFORCE_FIRST_AS);
	}

	for (ALL_LIST_ELEMENTS_RO(bgp->peer, node, peer)) {
		FOREACH_AFI_SAFI (afi, safi)
			peer_on_policy_change(peer, afi, safi, 0);
	}
	return NB_OK;
}

void bgp_nb_cli_show_enforce_first_as(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp enforce-first-as\n");
	else
		vty_out(vty, " no bgp enforce-first-as\n");
}

int bgp_nb_connected_route_check_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	/* YANG true => disable connected NH check */
	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_DISABLE_NH_CONNECTED_CHK);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_DISABLE_NH_CONNECTED_CHK);
	bgp_clear_all_soft_in(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_connected_route_check(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp disable-ebgp-connected-route-check\n");
	else if (show_defaults)
		vty_out(vty, " no bgp disable-ebgp-connected-route-check\n");
}

int bgp_nb_allow_outbound_policy_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	bool enable;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	enable = yang_dnode_get_bool(args->dnode, NULL);
	if (enable) {
		if (CHECK_FLAG(bgp->flags, BGP_FLAG_RR_ALLOW_OUTBOUND_POLICY))
			return NB_OK;
		SET_FLAG(bgp->flags, BGP_FLAG_RR_ALLOW_OUTBOUND_POLICY);
	} else {
		if (!CHECK_FLAG(bgp->flags, BGP_FLAG_RR_ALLOW_OUTBOUND_POLICY))
			return NB_OK;
		UNSET_FLAG(bgp->flags, BGP_FLAG_RR_ALLOW_OUTBOUND_POLICY);
	}
	update_group_announce_rrclients(bgp);
	bgp_clear_all_soft_out(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_allow_outbound_policy(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp route-reflector allow-outbound-policy\n");
	else if (show_defaults)
		vty_out(vty, " no bgp route-reflector allow-outbound-policy\n");
}

int bgp_nb_hard_admin_reset_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_HARD_ADMIN_RESET);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_HARD_ADMIN_RESET);
	return NB_OK;
}

void bgp_nb_cli_show_hard_admin_reset(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp hard-administrative-reset\n");
	else
		vty_out(vty, " no bgp hard-administrative-reset\n");
}

int bgp_nb_show_hostname_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_SHOW_HOSTNAME);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_SHOW_HOSTNAME);
	return NB_OK;
}

void bgp_nb_cli_show_show_hostname(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp default show-hostname\n");
	else if (show_defaults)
		vty_out(vty, " no bgp default show-hostname\n");
}

int bgp_nb_show_nexthop_hostname_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_SHOW_NEXTHOP_HOSTNAME);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_SHOW_NEXTHOP_HOSTNAME);
	return NB_OK;
}

void bgp_nb_cli_show_show_nexthop_hostname(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp default show-nexthop-hostname\n");
	else if (show_defaults)
		vty_out(vty, " no bgp default show-nexthop-hostname\n");
}

int bgp_nb_external_compare_router_id_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_COMPARE_ROUTER_ID);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_COMPARE_ROUTER_ID);
	bgp_recalculate_all_bestpaths(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_external_compare_router_id(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp bestpath compare-routerid\n");
	else if (show_defaults)
		vty_out(vty, " no bgp bestpath compare-routerid\n");
}

int bgp_nb_ignore_as_path_length_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_ASPATH_IGNORE);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_ASPATH_IGNORE);
	bgp_recalculate_all_bestpaths(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_ignore_as_path_length(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp bestpath as-path ignore\n");
	else if (show_defaults)
		vty_out(vty, " no bgp bestpath as-path ignore\n");
}

int bgp_nb_compare_aigp_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_COMPARE_AIGP);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_COMPARE_AIGP);
	bgp_recalculate_all_bestpaths(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_compare_aigp(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp bestpath aigp\n");
	else if (show_defaults)
		vty_out(vty, " no bgp bestpath aigp\n");
}

int bgp_nb_use_imported_attributes_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	bool enable;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	enable = yang_dnode_get_bool(args->dnode, NULL);
	if (enable == !!CHECK_FLAG(bgp->flags, BGP_FLAG_BESTPATH_USE_IMPORTED_ATTRS))
		return NB_OK;
	if (enable)
		SET_FLAG(bgp->flags, BGP_FLAG_BESTPATH_USE_IMPORTED_ATTRS);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_BESTPATH_USE_IMPORTED_ATTRS);
	bgp_recalculate_all_bestpaths(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_use_imported_attributes(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp bestpath use-imported-attributes\n");
	else if (show_defaults)
		vty_out(vty, " no bgp bestpath use-imported-attributes\n");
}

int bgp_nb_aspath_confed_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_ASPATH_CONFED);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_ASPATH_CONFED);
	bgp_recalculate_all_bestpaths(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_aspath_confed(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp bestpath as-path confed\n");
	else if (show_defaults)
		vty_out(vty, " no bgp bestpath as-path confed\n");
}

int bgp_nb_allow_multiple_as_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_ASPATH_MULTIPATH_RELAX);
	else {
		UNSET_FLAG(bgp->flags, BGP_FLAG_ASPATH_MULTIPATH_RELAX);
		UNSET_FLAG(bgp->flags, BGP_FLAG_MULTIPATH_RELAX_AS_SET);
	}
	bgp_recalculate_all_bestpaths(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_allow_multiple_as(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults)
{
	const struct lyd_node *parent = yang_dnode_get_parent(dnode, "route-selection-options");
	bool relax = yang_dnode_get_bool(dnode, NULL);

	/*
	 * multi-path-as-set defaults to false and is skipped by nb_cli_show,
	 * so "multipath-relax" with no as-set is printed here. When as-set is
	 * explicit, its callback prints the combined line.
	 */
	if (!relax) {
		if (show_defaults)
			vty_out(vty, " no bgp bestpath as-path multipath-relax\n");
		return;
	}
	if (parent && yang_dnode_exists(parent, "multi-path-as-set") &&
	    !yang_dnode_is_default(parent, "multi-path-as-set"))
		return;
	vty_out(vty, " bgp bestpath as-path multipath-relax\n");
}

int bgp_nb_multi_path_as_set_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_MULTIPATH_RELAX_AS_SET);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_MULTIPATH_RELAX_AS_SET);
	bgp_recalculate_all_bestpaths(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_multi_path_as_set(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults)
{
	const struct lyd_node *parent = yang_dnode_get_parent(dnode, "route-selection-options");
	bool relax;
	bool as_set;

	/* Default false is printed by allow-multiple-as, if at all. */
	if (yang_dnode_is_default(dnode, NULL))
		return;
	if (!parent)
		return;
	relax = yang_dnode_get_bool(parent, "allow-multiple-as");
	as_set = yang_dnode_get_bool(dnode, NULL);

	if (!relax)
		return;
	if (as_set)
		vty_out(vty, " bgp bestpath as-path multipath-relax as-set\n");
	else
		vty_out(vty, " bgp bestpath as-path multipath-relax\n");
}

int bgp_nb_peer_type_multipath_relax_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_PEERTYPE_MULTIPATH_RELAX);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_PEERTYPE_MULTIPATH_RELAX);
	bgp_recalculate_all_bestpaths(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_peer_type_multipath_relax(struct vty *vty, const struct lyd_node *dnode,
					       bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp bestpath peer-type multipath-relax\n");
	else if (show_defaults)
		vty_out(vty, " no bgp bestpath peer-type multipath-relax\n");
}

int bgp_nb_confed_med_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_MED_CONFED);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_MED_CONFED);
	bgp_recalculate_all_bestpaths(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_confed_med(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const struct lyd_node *parent = yang_dnode_get_parent(dnode, "route-selection-options");

	if (!yang_dnode_get_bool(dnode, NULL))
		return;
	/*
	 * missing-as-worst-med prints the combined line when it is set.
	 * While that leaf is still the default, nb_cli_show skips it, so
	 * "bgp bestpath med confed" has to be printed from here.
	 */
	if (parent && yang_dnode_exists(parent, "missing-as-worst-med") &&
	    !yang_dnode_is_default(parent, "missing-as-worst-med"))
		return;
	vty_out(vty, " bgp bestpath med confed\n");
}

int bgp_nb_missing_as_worst_med_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_MED_MISSING_AS_WORST);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_MED_MISSING_AS_WORST);
	bgp_recalculate_all_bestpaths(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_missing_as_worst_med(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults)
{
	const struct lyd_node *parent = yang_dnode_get_parent(dnode, "route-selection-options");
	bool confed = false;
	bool missing;

	/* Default false must not reprint a confed-only line. */
	if (yang_dnode_is_default(dnode, NULL))
		return;
	if (!parent)
		return;
	missing = yang_dnode_get_bool(dnode, NULL);
	if (yang_dnode_exists(parent, "confed-med"))
		confed = yang_dnode_get_bool(parent, "confed-med");

	if (confed && missing)
		vty_out(vty, " bgp bestpath med confed missing-as-worst\n");
	else if (missing)
		vty_out(vty, " bgp bestpath med missing-as-worst\n");
}

int bgp_nb_bandwidth_handling_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *val;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	val = yang_dnode_get_string(args->dnode, NULL);
	if (strmatch(val, "ignore"))
		bgp->lb_handling = BGP_LINK_BW_IGNORE_BW;
	else if (strmatch(val, "skip-missing"))
		bgp->lb_handling = BGP_LINK_BW_SKIP_MISSING;
	else if (strmatch(val, "default-weight-for-missing"))
		bgp->lb_handling = BGP_LINK_BW_DEFWT_4_MISSING;
	else
		bgp->lb_handling = BGP_LINK_BW_ECMP;

	FOREACH_AFI_SAFI (afi, safi) {
		if (!bgp_fibupd_safi(safi))
			continue;
		bgp_zebra_announce_table(bgp, afi, safi);
	}
	return NB_OK;
}

void bgp_nb_cli_show_bandwidth_handling(struct vty *vty, const struct lyd_node *dnode,
					bool show_defaults)
{
	const char *val = yang_dnode_get_string(dnode, NULL);

	if (strmatch(val, "ecmp")) {
		if (show_defaults)
			vty_out(vty, " no bgp bestpath bandwidth\n");
		return;
	}
	vty_out(vty, " bgp bestpath bandwidth %s\n", val);
}

static void bgp_nb_apply_global_timers(struct bgp *bgp, const struct lyd_node *dnode)
{
	const struct lyd_node *timers;
	uint32_t keepalive;
	uint32_t holdtime;

	timers = yang_dnode_get_parent(dnode, "global-config-timers");
	keepalive = yang_dnode_get_uint16(timers, "keepalive");
	holdtime = yang_dnode_get_uint16(timers, "hold-time");
	bgp_timers_set(NULL, bgp, keepalive, holdtime, DFLT_BGP_CONNECT_RETRY,
		       BGP_DEFAULT_DELAYOPEN);
}

int bgp_nb_keepalive_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp_nb_apply_global_timers(bgp, args->dnode);
	return NB_OK;
}

int bgp_nb_hold_time_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE: {
		uint16_t holdtime = yang_dnode_get_uint16(args->dnode, NULL);

		if (holdtime < 3 && holdtime != 0) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "hold time value must be either 0 or greater than 3");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	}
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp_nb_apply_global_timers(bgp, args->dnode);
	return NB_OK;
}

void bgp_nb_cli_show_keepalive(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const struct lyd_node *timers = yang_dnode_get_parent(dnode, "global-config-timers");
	uint16_t keepalive = yang_dnode_get_uint16(dnode, NULL);
	uint16_t holdtime = yang_dnode_get_uint16(timers, "hold-time");

	if (keepalive != DFLT_BGP_KEEPALIVE || holdtime != DFLT_BGP_HOLDTIME || show_defaults)
		vty_out(vty, " timers bgp %u %u\n", keepalive, holdtime);
}

void bgp_nb_cli_show_holdtime(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const struct lyd_node *timers = yang_dnode_get_parent(dnode, "global-config-timers");
	const struct lyd_node *ka;
	uint16_t keepalive, holdtime;

	/*
	 * Keepalive owns this line when nb_cli_show will visit it. A default
	 * keepalive is skipped, which dropped "timers bgp 60 <hold>".
	 */
	ka = timers ? yang_dnode_get(timers, "keepalive") : NULL;
	if (ka && (show_defaults || !yang_dnode_is_default(ka, NULL)))
		return;

	keepalive = ka ? yang_dnode_get_uint16(ka, NULL) : DFLT_BGP_KEEPALIVE;
	holdtime = yang_dnode_get_uint16(dnode, NULL);
	if (keepalive != DFLT_BGP_KEEPALIVE || holdtime != DFLT_BGP_HOLDTIME || show_defaults)
		vty_out(vty, " timers bgp %u %u\n", keepalive, holdtime);
}

int bgp_nb_minimum_holdtime_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp->default_min_holdtime = yang_dnode_get_uint16(args->dnode, NULL);
	return NB_OK;
}

int bgp_nb_minimum_holdtime_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp->default_min_holdtime = 0;
	return NB_OK;
}

void bgp_nb_cli_show_minimum_holdtime(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults)
{
	vty_out(vty, " bgp minimum-holdtime %u\n", yang_dnode_get_uint16(dnode, NULL));
}

int bgp_nb_confederation_identifier_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp_confederation_id_set(bgp, yang_dnode_get_uint32(args->dnode, NULL),
				 yang_dnode_get_string(args->dnode, NULL));
	return NB_OK;
}

int bgp_nb_confederation_identifier_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp_confederation_id_unset(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_confederation_identifier(struct vty *vty, const struct lyd_node *dnode,
					      bool show_defaults)
{
	vty_out(vty, " bgp confederation identifier %s\n", yang_dnode_get_string(dnode, NULL));
}

int bgp_nb_confederation_member_as_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp_confederation_peers_add(bgp, yang_dnode_get_uint32(args->dnode, NULL),
				    yang_dnode_get_string(args->dnode, NULL));
	return NB_OK;
}

int bgp_nb_confederation_member_as_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp_confederation_peers_remove(bgp, yang_dnode_get_uint32(args->dnode, NULL));
	return NB_OK;
}

void bgp_nb_cli_show_confederation_member_as(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults)
{
	vty_out(vty, " bgp confederation peers %s\n", yang_dnode_get_string(dnode, NULL));
}

int bgp_nb_enable_med_admin_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (yang_dnode_get_bool(args->dnode, NULL))
		bgp->v_maxmed_admin = 1;
	else {
		bgp->v_maxmed_admin = BGP_MAXMED_ADMIN_UNCONFIGURED;
		bgp->maxmed_admin_value = BGP_MAXMED_VALUE_DEFAULT;
	}
	bgp_maxmed_update(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_enable_med_admin(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults)
{
	const struct lyd_node *med = yang_dnode_get_parent(dnode, "med-config");
	uint32_t value;

	if (!yang_dnode_get_bool(dnode, NULL))
		return;

	/*
	 * This leaf is false by default, so the callback runs whenever
	 * administrative max-med is on. max-med-admin itself is skipped when
	 * it stays at the default, which dropped the bare command.
	 */
	value = (med && yang_dnode_exists(med, "max-med-admin"))
		? yang_dnode_get_uint32(med, "max-med-admin")
		: BGP_MAXMED_VALUE_DEFAULT;
	if (value == BGP_MAXMED_VALUE_DEFAULT)
		vty_out(vty, " bgp max-med administrative\n");
	else
		vty_out(vty, " bgp max-med administrative %u\n", value);
}

int bgp_nb_max_med_admin_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const struct lyd_node *med;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	med = yang_dnode_get_parent(args->dnode, "med-config");
	if (!yang_dnode_get_bool(med, "enable-med-admin"))
		return NB_OK;

	bgp->maxmed_admin_value = yang_dnode_get_uint32(args->dnode, NULL);
	bgp_maxmed_update(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_max_med_admin(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults)
{
	/*
	 * Printed by bgp_nb_cli_show_enable_med_admin. enable-med-admin is not a
	 * default whenever the command is configured, including when this value
	 * stays at BGP_MAXMED_VALUE_DEFAULT.
	 */
}

int bgp_nb_max_med_onstartup_time_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const struct lyd_node *med;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	med = yang_dnode_get_parent(args->dnode, "med-config");
	bgp->v_maxmed_onstartup = yang_dnode_get_uint32(args->dnode, NULL);
	if (yang_dnode_exists(med, "max-med-onstart-up-value"))
		bgp->maxmed_onstartup_value = yang_dnode_get_uint32(med,
								    "max-med-onstart-up-value");
	else
		bgp->maxmed_onstartup_value = BGP_MAXMED_VALUE_DEFAULT;
	bgp_maxmed_update(bgp);
	return NB_OK;
}

int bgp_nb_max_med_onstartup_time_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (event_is_scheduled(bgp->t_maxmed_onstartup)) {
		event_cancel(&bgp->t_maxmed_onstartup);
		bgp->maxmed_onstartup_over = 1;
	}
	bgp->v_maxmed_onstartup = BGP_MAXMED_ONSTARTUP_UNCONFIGURED;
	bgp->maxmed_onstartup_value = BGP_MAXMED_VALUE_DEFAULT;
	bgp_maxmed_update(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_max_med_onstartup_time(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults)
{
	const struct lyd_node *med = yang_dnode_get_parent(dnode, "med-config");
	uint32_t time = yang_dnode_get_uint32(dnode, NULL);
	uint32_t value = BGP_MAXMED_VALUE_DEFAULT;

	if (yang_dnode_exists(med, "max-med-onstart-up-value"))
		value = yang_dnode_get_uint32(med, "max-med-onstart-up-value");

	if (value == BGP_MAXMED_VALUE_DEFAULT)
		vty_out(vty, " bgp max-med on-startup %u\n", time);
	else
		vty_out(vty, " bgp max-med on-startup %u %u\n", time, value);
}

int bgp_nb_max_med_onstartup_value_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const struct lyd_node *med;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	med = yang_dnode_get_parent(args->dnode, "med-config");
	if (!yang_dnode_exists(med, "max-med-onstart-up-time"))
		return NB_OK;

	bgp->maxmed_onstartup_value = yang_dnode_get_uint32(args->dnode, NULL);
	bgp_maxmed_update(bgp);
	return NB_OK;
}

int bgp_nb_update_delay_time_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const struct lyd_node *timers;
	uint16_t delay;
	uint16_t wait;

	delay = yang_dnode_get_uint16(args->dnode, NULL);
	timers = yang_dnode_get_parent(args->dnode, "global-config-timers");
	if (yang_dnode_exists(timers, "establish-wait-time"))
		wait = yang_dnode_get_uint16(timers, "establish-wait-time");
	else
		wait = delay;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (bm->v_update_delay) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "per-vrf update-delay not permitted with global update-delay");
			return NB_ERR_VALIDATION;
		}
		if (delay < wait) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "update-delay less than the establish-wait");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp->v_update_delay = delay;
	bgp->v_establish_wait = wait;
	return NB_OK;
}

int bgp_nb_update_delay_time_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (bm->v_update_delay) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "cannot remove per-vrf update-delay while global update-delay is set");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp->v_update_delay = BGP_UPDATE_DELAY_DEFAULT;
	bgp->v_establish_wait = BGP_UPDATE_DELAY_DEFAULT;
	return NB_OK;
}

void bgp_nb_cli_show_update_delay_time(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults)
{
	const struct lyd_node *timers = yang_dnode_get_parent(dnode, "global-config-timers");
	uint16_t delay = yang_dnode_get_uint16(dnode, NULL);
	uint16_t wait = delay;

	if (yang_dnode_exists(timers, "establish-wait-time"))
		wait = yang_dnode_get_uint16(timers, "establish-wait-time");

	if (wait != delay)
		vty_out(vty, " update-delay %u %u\n", delay, wait);
	else
		vty_out(vty, " update-delay %u\n", delay);
}

int bgp_nb_establish_wait_time_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const struct lyd_node *timers;
	uint16_t delay;
	uint16_t wait;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	timers = yang_dnode_get_parent(args->dnode, "global-config-timers");
	if (!yang_dnode_exists(timers, "update-delay-time"))
		return NB_OK;

	delay = yang_dnode_get_uint16(timers, "update-delay-time");
	wait = yang_dnode_get_uint16(args->dnode, NULL);
	bgp->v_update_delay = delay;
	bgp->v_establish_wait = wait;
	return NB_OK;
}

int bgp_nb_establish_wait_time_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const struct lyd_node *timers;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	timers = yang_dnode_get_parent(args->dnode, "global-config-timers");
	if (yang_dnode_exists(timers, "update-delay-time"))
		bgp->v_establish_wait = yang_dnode_get_uint16(timers, "update-delay-time");
	else
		bgp->v_establish_wait = BGP_UPDATE_DELAY_DEFAULT;
	return NB_OK;
}

int bgp_nb_advertisement_delay_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp->v_advertisement_delay = yang_dnode_get_uint16(args->dnode, NULL);
	return NB_OK;
}

int bgp_nb_advertisement_delay_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp->v_advertisement_delay = BGP_ADVERTISEMENT_DELAY_DEFAULT;
	if (bgp->advertisement_delay_started && !bgp->advertisement_delay_over) {
		event_cancel(&bgp->t_advertisement_delay);
		bgp->advertisement_delay_started = 0;
		bgp->advertisement_delay_over = 0;
		if (!bgp_update_delay_active(bgp) && !bgp->main_zebra_update_hold) {
			bgp->main_peers_update_hold = 0;
			bgp_start_routeadv(bgp);
		}
	} else {
		event_cancel(&bgp->t_advertisement_delay);
		bgp->advertisement_delay_started = 0;
		bgp->advertisement_delay_over = 0;
	}
	return NB_OK;
}

void bgp_nb_cli_show_advertisement_delay(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults)
{
	vty_out(vty, " advertisement-delay %u\n", yang_dnode_get_uint16(dnode, NULL));
}

int bgp_nb_dynamic_neighbors_limit_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp_listen_limit_set(bgp, yang_dnode_get_uint32(args->dnode, NULL));
	return NB_OK;
}

int bgp_nb_dynamic_neighbors_limit_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp_listen_limit_unset(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_dynamic_neighbors_limit(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults)
{
	uint32_t limit = yang_dnode_get_uint32(dnode, NULL);

	if (limit != BGP_DYNAMIC_NEIGHBORS_LIMIT_DEFAULT || show_defaults)
		vty_out(vty, " bgp listen limit %u\n", limit);
}

static int bgp_nb_parse_default_afi_safi(const char *afi_safi, afi_t *afi, safi_t *safi,
					 char *errmsg, size_t errmsg_len)
{
	char buf[64];
	char *tok = NULL;
	char *afi_str;
	char *safi_str;

	strlcpy(buf, afi_safi, sizeof(buf));
	afi_str = strtok_r(buf, "-", &tok);
	safi_str = strtok_r(NULL, "-", &tok);
	if (!afi_str || !safi_str) {
		snprintfrr(errmsg, errmsg_len, "Invalid AFI/SAFI %s", afi_safi);
		return NB_ERR_VALIDATION;
	}

	*afi = bgp_vty_afi_from_str(afi_str);
	if (*afi == AFI_MAX) {
		snprintfrr(errmsg, errmsg_len, "Invalid AFI in %s", afi_safi);
		return NB_ERR_VALIDATION;
	}

	if (strmatch(safi_str, "labeled"))
		*safi = bgp_vty_safi_from_str("labeled-unicast");
	else
		*safi = bgp_vty_safi_from_str(safi_str);

	if (*safi == SAFI_MAX) {
		snprintfrr(errmsg, errmsg_len, "Invalid SAFI in %s", afi_safi);
		return NB_ERR_VALIDATION;
	}
	return NB_OK;
}

int bgp_nb_default_afi_safi_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	int ret;

	ret = bgp_nb_parse_default_afi_safi(yang_dnode_get_string(args->dnode, NULL), &afi, &safi,
					    args->errmsg, args->errmsg_len);
	if (ret != NB_OK)
		return ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
		bgp = nb_running_get_entry(args->dnode, NULL, false);
		if (!bgp)
			return NB_OK;
		if ((safi == SAFI_LABELED_UNICAST && bgp->default_af[afi][SAFI_UNICAST]) ||
		    (safi == SAFI_UNICAST && bgp->default_af[afi][SAFI_LABELED_UNICAST])) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "Cannot activate both unicast and labeled-unicast by default");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp->default_af[afi][safi] = true;
	return NB_OK;
}

int bgp_nb_default_afi_safi_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	int ret;

	ret = bgp_nb_parse_default_afi_safi(yang_dnode_get_string(args->dnode, NULL), &afi, &safi,
					    args->errmsg, args->errmsg_len);
	if (ret != NB_OK)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp->default_af[afi][safi] = false;
	return NB_OK;
}

void bgp_nb_cli_show_default_afi_safi(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults)
{
	vty_out(vty, " bgp default %s\n", yang_dnode_get_string(dnode, NULL));
}

int bgp_nb_gr_stale_routes_time_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp->stalepath_time = yang_dnode_get_uint16(args->dnode, NULL);
	return NB_OK;
}

void bgp_nb_cli_show_gr_stale_routes_time(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults)
{
	uint16_t val = yang_dnode_get_uint16(dnode, NULL);

	if (val != BGP_DEFAULT_STALEPATH_TIME || show_defaults)
		vty_out(vty, " bgp graceful-restart stalepath-time %u\n", val);
}

static void bgp_nb_gr_restart_time_peers(struct bgp *bgp, bool unset)
{
	struct listnode *node, *nnode;
	struct peer *peer;

	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
		if (!CHECK_FLAG(peer->cap, PEER_CAP_DYNAMIC_RCV) ||
		    !CHECK_FLAG(peer->cap, PEER_CAP_DYNAMIC_ADV))
			bgp_update_graceful_restart_capability(peer);
		else
			bgp_capability_send(peer->connection, AFI_IP, SAFI_UNICAST,
					    CAPABILITY_CODE_RESTART,
					    unset ? CAPABILITY_ACTION_UNSET
						  : CAPABILITY_ACTION_SET);
	}
}

int bgp_nb_gr_restart_time_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp->restart_time = yang_dnode_get_uint16(args->dnode, NULL);
	bgp_nb_gr_restart_time_peers(bgp, false);
	return NB_OK;
}

void bgp_nb_cli_show_gr_restart_time(struct vty *vty, const struct lyd_node *dnode,
				     bool show_defaults)
{
	uint16_t val = yang_dnode_get_uint16(dnode, NULL);

	if (val != BGP_DEFAULT_RESTART_TIME || show_defaults)
		vty_out(vty, " bgp graceful-restart restart-time %u\n", val);
}

int bgp_nb_gr_select_defer_time_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	uint16_t defer_time;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	defer_time = yang_dnode_get_uint16(args->dnode, NULL);
	bgp->select_defer_time = defer_time;
	if (defer_time == 0)
		SET_FLAG(bgp->flags, BGP_FLAG_SELECT_DEFER_DISABLE);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_SELECT_DEFER_DISABLE);
	return NB_OK;
}

void bgp_nb_cli_show_gr_select_defer_time(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults)
{
	uint16_t val = yang_dnode_get_uint16(dnode, NULL);

	if (val != BGP_DEFAULT_SELECT_DEFERRAL_TIME || show_defaults)
		vty_out(vty, " bgp graceful-restart select-defer-time %u\n", val);
}

int bgp_nb_gr_rib_stale_time_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp->rib_stale_time = yang_dnode_get_uint16(args->dnode, NULL);
	bgp_zebra_stale_timer_update(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_gr_rib_stale_time(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults)
{
	uint16_t val = yang_dnode_get_uint16(dnode, NULL);

	if (val != BGP_DEFAULT_RIB_STALE_TIME || show_defaults)
		vty_out(vty, " bgp graceful-restart rib-stale-time %u\n", val);
}

int bgp_nb_gr_preserve_fw_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_GR_PRESERVE_FWD);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_GR_PRESERVE_FWD);
	return NB_OK;
}

void bgp_nb_cli_show_gr_preserve_fw(struct vty *vty, const struct lyd_node *dnode,
				    bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp graceful-restart preserve-fw-state\n");
	else if (show_defaults)
		vty_out(vty, " no bgp graceful-restart preserve-fw-state\n");
}

int bgp_nb_gr_notification_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct listnode *node, *nnode;
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_NOTIFICATION);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_NOTIFICATION);

	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer))
		bgp_capability_send(peer->connection, AFI_IP, SAFI_UNICAST,
				    CAPABILITY_CODE_RESTART, CAPABILITY_ACTION_SET);
	return NB_OK;
}

int bgp_nb_gr_notification_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	struct listnode *node, *nnode;
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	UNSET_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_NOTIFICATION);
	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer))
		bgp_capability_send(peer->connection, AFI_IP, SAFI_UNICAST,
				    CAPABILITY_CODE_RESTART, CAPABILITY_ACTION_SET);
	return NB_OK;
}

void bgp_nb_cli_show_gr_notification(struct vty *vty, const struct lyd_node *dnode,
				     bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp graceful-restart notification\n");
	else
		vty_out(vty, " no bgp graceful-restart notification\n");
}

int bgp_nb_gr_disable_eor_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_GR_DISABLE_EOR);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_GR_DISABLE_EOR);
	return NB_OK;
}

void bgp_nb_cli_show_gr_disable_eor(struct vty *vty, const struct lyd_node *dnode,
				    bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp graceful-restart disable-eor\n");
	else if (show_defaults)
		vty_out(vty, " no bgp graceful-restart disable-eor\n");
}

int bgp_nb_gr_llgr_stale_time_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct listnode *node, *nnode;
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp->llgr_stale_time = yang_dnode_get_uint32(args->dnode, NULL);
	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer))
		bgp_capability_send(peer->connection, AFI_IP, SAFI_UNICAST, CAPABILITY_CODE_LLGR,
				    CAPABILITY_ACTION_SET);
	return NB_OK;
}

void bgp_nb_cli_show_gr_llgr_stale_time(struct vty *vty, const struct lyd_node *dnode,
					bool show_defaults)
{
	uint32_t val = yang_dnode_get_uint32(dnode, NULL);

	if (val != BGP_DEFAULT_LLGR_STALE_TIME || show_defaults)
		vty_out(vty, " bgp long-lived-graceful-restart stale-time %u\n", val);
}

int bgp_nb_gr_enabled_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	int ret;

	bool enable;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	enable = yang_dnode_get_bool(args->dnode, NULL);
	bgp = nb_running_get_entry(args->dnode, NULL, true);
	ret = bgp_inst_gr_config(bgp, enable, false);
	if (ret != BGP_GR_SUCCESS) {
		snprintfrr(args->errmsg, args->errmsg_len,
			   enable ? "Failed to enable graceful-restart"
				  : "Failed to disable graceful-restart");
		return NB_ERR;
	}
	return NB_OK;
}

int bgp_nb_gr_enabled_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	int ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	ret = bgp_inst_gr_config(bgp, false, false);
	if (ret != BGP_GR_SUCCESS) {
		snprintfrr(args->errmsg, args->errmsg_len, "Failed to disable graceful-restart");
		return NB_ERR;
	}
	return NB_OK;
}

void bgp_nb_cli_show_gr_enabled(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp graceful-restart\n");
}

int bgp_nb_gr_disable_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct listnode *node, *nnode;
	struct peer *peer;
	int ret;

	bool disable;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	disable = yang_dnode_get_bool(args->dnode, NULL);
	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!disable) {
		ret = bgp_inst_gr_config(bgp, false, true);
		if (ret != BGP_GR_SUCCESS) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "Failed to clear graceful-restart-disable");
			return NB_ERR;
		}
		return NB_OK;
	}

	ret = bgp_inst_gr_config(bgp, true, true);
	if (ret != BGP_GR_SUCCESS) {
		snprintfrr(args->errmsg, args->errmsg_len,
			   "Failed to disable graceful-restart globally");
		return NB_ERR;
	}
	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
		bgp_capability_send(peer->connection, AFI_IP, SAFI_UNICAST,
				    CAPABILITY_CODE_RESTART, CAPABILITY_ACTION_UNSET);
		bgp_capability_send(peer->connection, AFI_IP, SAFI_UNICAST, CAPABILITY_CODE_LLGR,
				    CAPABILITY_ACTION_UNSET);
	}
	return NB_OK;
}

int bgp_nb_gr_disable_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	int ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	ret = bgp_inst_gr_config(bgp, false, true);
	if (ret != BGP_GR_SUCCESS) {
		snprintfrr(args->errmsg, args->errmsg_len,
			   "Failed to clear graceful-restart-disable");
		return NB_ERR;
	}
	return NB_OK;
}

void bgp_nb_cli_show_gr_disable(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp graceful-restart-disable\n");
}

static void bgp_nb_tcp_keepalive_apply(struct bgp *bgp, const struct lyd_node *dnode)
{
	const struct lyd_node *ka = yang_dnode_get_parent(dnode, "tcp-keepalive");

	if (!yang_dnode_exists(ka, "idle") || !yang_dnode_exists(ka, "interval") ||
	    !yang_dnode_exists(ka, "probes"))
		return;

	bgp_tcp_keepalive_set(bgp, yang_dnode_get_uint16(ka, "idle"),
			      yang_dnode_get_uint16(ka, "interval"),
			      yang_dnode_get_uint8(ka, "probes"));
}

static void bgp_nb_tcp_keepalive_clear_if_empty(struct bgp *bgp, const struct lyd_node *dnode)
{
	const struct lyd_node *ka = yang_dnode_get_parent(dnode, "tcp-keepalive");

	if (yang_dnode_exists(ka, "idle") || yang_dnode_exists(ka, "interval") ||
	    yang_dnode_exists(ka, "probes"))
		return;

	bgp_tcp_keepalive_unset(bgp);
}

int bgp_nb_tcp_keepalive_idle_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp_nb_tcp_keepalive_apply(bgp, args->dnode);
	return NB_OK;
}

int bgp_nb_tcp_keepalive_idle_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp_nb_tcp_keepalive_clear_if_empty(bgp, args->dnode);
	return NB_OK;
}

int bgp_nb_tcp_keepalive_interval_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp_nb_tcp_keepalive_apply(bgp, args->dnode);
	return NB_OK;
}

int bgp_nb_tcp_keepalive_interval_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp_nb_tcp_keepalive_clear_if_empty(bgp, args->dnode);
	return NB_OK;
}

int bgp_nb_tcp_keepalive_probes_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp_nb_tcp_keepalive_apply(bgp, args->dnode);
	return NB_OK;
}

int bgp_nb_tcp_keepalive_probes_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp_nb_tcp_keepalive_clear_if_empty(bgp, args->dnode);
	return NB_OK;
}

void bgp_nb_cli_show_tcp_keepalive_idle(struct vty *vty, const struct lyd_node *dnode,
					bool show_defaults)
{
	const struct lyd_node *ka = yang_dnode_get_parent(dnode, "tcp-keepalive");

	if (!yang_dnode_exists(ka, "interval") || !yang_dnode_exists(ka, "probes"))
		return;

	vty_out(vty, " bgp tcp-keepalive %u %u %u\n", yang_dnode_get_uint16(dnode, NULL),
		yang_dnode_get_uint16(ka, "interval"), yang_dnode_get_uint8(ka, "probes"));
}

int bgp_nb_wpkt_quanta_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	atomic_store_explicit(&bgp->wpkt_quanta, yang_dnode_get_uint32(args->dnode, NULL),
			      memory_order_relaxed);
	return NB_OK;
}

void bgp_nb_cli_show_wpkt_quanta(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	uint32_t quanta = yang_dnode_get_uint32(dnode, NULL);

	if (quanta != BGP_WRITE_PACKET_MAX || show_defaults)
		vty_out(vty, " write-quanta %u\n", quanta);
}

int bgp_nb_rpkt_quanta_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	atomic_store_explicit(&bgp->rpkt_quanta, yang_dnode_get_uint32(args->dnode, NULL),
			      memory_order_relaxed);
	return NB_OK;
}

void bgp_nb_cli_show_rpkt_quanta(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	uint32_t quanta = yang_dnode_get_uint32(dnode, NULL);

	if (quanta != BGP_READ_PACKET_MAX || show_defaults)
		vty_out(vty, " read-quanta %u\n", quanta);
}

int bgp_nb_coalesce_time_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	uint32_t value;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	value = yang_dnode_get_uint32(args->dnode, NULL);
	if (value == BGP_DEFAULT_SUBGROUP_COALESCE_TIME) {
		bgp->heuristic_coalesce = true;
		bgp->coalesce_time = BGP_DEFAULT_SUBGROUP_COALESCE_TIME;
	} else {
		bgp->heuristic_coalesce = false;
		bgp->coalesce_time = value;
	}
	return NB_OK;
}

void bgp_nb_cli_show_coalesce_time(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults)
{
	uint32_t value = yang_dnode_get_uint32(dnode, NULL);

	if (value != BGP_DEFAULT_SUBGROUP_COALESCE_TIME || show_defaults)
		vty_out(vty, " coalesce-time %u\n", value);
}

int bgp_nb_subgroup_pkt_queue_size_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	uint32_t value;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	value = yang_dnode_get_uint32(args->dnode, NULL);
	if (value == BGP_DEFAULT_SUBGROUP_PKT_QUEUE_MAX)
		bgp_default_subgroup_pkt_queue_max_unset(bgp);
	else
		bgp_default_subgroup_pkt_queue_max_set(bgp, value);
	return NB_OK;
}

void bgp_nb_cli_show_subgroup_pkt_queue_size(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults)
{
	uint32_t value = yang_dnode_get_uint32(dnode, NULL);

	if (value != BGP_DEFAULT_SUBGROUP_PKT_QUEUE_MAX || show_defaults)
		vty_out(vty, " bgp default subgroup-pkt-queue-max %u\n", value);
}

int bgp_nb_default_shutdown_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp->autoshutdown = yang_dnode_get_bool(args->dnode, NULL);
	return NB_OK;
}

void bgp_nb_cli_show_default_shutdown(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp default shutdown\n");
	else if (show_defaults)
		vty_out(vty, " no bgp default shutdown\n");
}

/* Whether administrative shutdown should send BGP NOTIFICATION messages. */
static bool bgp_nb_shutdown_send_notify(const struct lyd_node *global)
{
	if (yang_dnode_exists(global, "shutdown-no-notify") &&
	    yang_dnode_get_bool(global, "shutdown-no-notify"))
		return false;
	return true;
}

int bgp_nb_shutdown_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const struct lyd_node *global;
	const char *msg = NULL;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	global = yang_dnode_get_parent(args->dnode, "global");
	if (yang_dnode_get_bool(args->dnode, NULL)) {
		if (yang_dnode_exists(global, "shutdown-message"))
			msg = yang_dnode_get_string(global, "shutdown-message");
		bgp_shutdown_enable(bgp, msg, bgp_nb_shutdown_send_notify(global));
	} else
		bgp_shutdown_disable(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_shutdown(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const struct lyd_node *global = yang_dnode_get_parent(dnode, "global");

	if (!yang_dnode_get_bool(dnode, NULL))
		return;
	if (yang_dnode_exists(global, "shutdown-message"))
		return; /* shown by shutdown-message */
	if (!bgp_nb_shutdown_send_notify(global))
		return; /* shown by shutdown-no-notify */
	vty_out(vty, " bgp shutdown\n");
}

int bgp_nb_shutdown_message_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const struct lyd_node *global;
	const char *msg;

	switch (args->event) {
	case NB_EV_VALIDATE:
		msg = yang_dnode_get_string(args->dnode, NULL);
		if (strlen(msg) > BGP_ADMIN_SHUTDOWN_MSG_LEN) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "Shutdown message size exceeded %d", BGP_ADMIN_SHUTDOWN_MSG_LEN);
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	global = yang_dnode_get_parent(args->dnode, "global");
	bgp_shutdown_enable(bgp, yang_dnode_get_string(args->dnode, NULL),
			    bgp_nb_shutdown_send_notify(global));
	return NB_OK;
}

int bgp_nb_shutdown_message_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const struct lyd_node *global;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	global = yang_dnode_get_parent(args->dnode, "global");
	if (yang_dnode_exists(global, "shutdown") && yang_dnode_get_bool(global, "shutdown"))
		bgp_shutdown_enable(bgp, NULL, bgp_nb_shutdown_send_notify(global));
	return NB_OK;
}

void bgp_nb_cli_show_shutdown_message(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults)
{
	vty_out(vty, " bgp shutdown message %s\n", yang_dnode_get_string(dnode, NULL));
}

/*
 * "bgp shutdown no-notify": the value is consumed by the shutdown /
 * shutdown-message callbacks when the instance is shut down, so there is
 * nothing to do here other than accept the configuration.
 */
int bgp_nb_shutdown_no_notify_modify(struct nb_cb_modify_args *args)
{
	return NB_OK;
}

int bgp_nb_shutdown_no_notify_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

void bgp_nb_cli_show_shutdown_no_notify(struct vty *vty, const struct lyd_node *dnode,
					bool show_defaults)
{
	const struct lyd_node *global = yang_dnode_get_parent(dnode, "global");

	if (!yang_dnode_get_bool(dnode, NULL))
		return;
	if (yang_dnode_exists(global, "shutdown") && yang_dnode_get_bool(global, "shutdown"))
		vty_out(vty, " bgp shutdown no-notify\n");
}

int bgp_nb_allow_martian_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp->allow_martian = yang_dnode_get_bool(args->dnode, NULL);
	return NB_OK;
}

void bgp_nb_cli_show_allow_martian(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp allow-martian-nexthop\n");
	else if (show_defaults)
		vty_out(vty, " no bgp allow-martian-nexthop\n");
}

int bgp_nb_use_underlays_nexthop_weight_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_USE_RECURSIVE_WEIGHT);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_USE_RECURSIVE_WEIGHT);
	return NB_OK;
}

void bgp_nb_cli_show_use_underlays_nexthop_weight(struct vty *vty, const struct lyd_node *dnode,
						  bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " use-underlays-nexthop-weight\n");
	else if (show_defaults)
		vty_out(vty, " no use-underlays-nexthop-weight\n");
}

int bgp_nb_suppress_fib_pending_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	bool set;
	uint16_t delay = BGP_DEFAULT_SUPPRESS_FIB_ADV_DELAY;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	set = yang_dnode_get_bool(args->dnode, NULL);
	if (set && yang_dnode_exists(args->dnode, "../suppress-fib-pending-delay"))
		delay = yang_dnode_get_uint16(args->dnode, "../suppress-fib-pending-delay");
	else if (set)
		delay = bgp->suppress_fib_adv_delay;

	bgp_suppress_fib_pending_set(bgp, set, delay);
	return NB_OK;
}

void bgp_nb_cli_show_suppress_fib_pending(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults)
{
	/* Printed with suppress-fib-pending-delay when enabled. */
	if (!yang_dnode_get_bool(dnode, NULL) && show_defaults)
		vty_out(vty, " no bgp suppress-fib-pending\n");
}

int bgp_nb_suppress_fib_pending_delay_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	uint16_t delay;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	delay = yang_dnode_get_uint16(args->dnode, NULL);
	bgp_suppress_fib_pending_set(bgp, true, delay);
	return NB_OK;
}

int bgp_nb_suppress_fib_pending_delay_destroy(struct nb_cb_destroy_args *args)
{
	/* Cleared via suppress-fib-pending = false. */
	return NB_OK;
}

void bgp_nb_cli_show_suppress_fib_pending_delay(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults)
{
	uint16_t delay = yang_dnode_get_uint16(dnode, NULL);

	if (delay != BGP_DEFAULT_SUPPRESS_FIB_ADV_DELAY)
		vty_out(vty, " bgp suppress-fib-pending %u\n", delay);
	else
		vty_out(vty, " bgp suppress-fib-pending\n");
}

int bgp_nb_fast_convergence_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp->fast_convergence = yang_dnode_get_bool(args->dnode, NULL);
	return NB_OK;
}

void bgp_nb_cli_show_fast_convergence(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp fast-convergence\n");
	else if (show_defaults)
		vty_out(vty, " no bgp fast-convergence\n");
}

int bgp_nb_ipv6_auto_ra_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	/* YANG true => allow RA; C flag is inverted (NO_AUTO_RA). */
	if (yang_dnode_get_bool(args->dnode, NULL))
		UNSET_FLAG(bgp->flags, BGP_FLAG_IPV6_NO_AUTO_RA);
	else
		SET_FLAG(bgp->flags, BGP_FLAG_IPV6_NO_AUTO_RA);
	return NB_OK;
}

void bgp_nb_cli_show_ipv6_auto_ra(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no bgp ipv6-auto-ra\n");
	else if (show_defaults)
		vty_out(vty, " bgp ipv6-auto-ra\n");
}

int bgp_nb_labeled_unicast_explicit_null_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *val;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	val = yang_dnode_get_string(args->dnode, NULL);

	UNSET_FLAG(bgp->flags, BGP_FLAG_LU_IPV4_EXPLICIT_NULL | BGP_FLAG_LU_IPV6_EXPLICIT_NULL);

	if (strmatch(val, "explicit-null"))
		SET_FLAG(bgp->flags,
			 BGP_FLAG_LU_IPV4_EXPLICIT_NULL | BGP_FLAG_LU_IPV6_EXPLICIT_NULL);
	else if (strmatch(val, "ipv4-explicit-null"))
		SET_FLAG(bgp->flags, BGP_FLAG_LU_IPV4_EXPLICIT_NULL);
	else if (strmatch(val, "ipv6-explicit-null"))
		SET_FLAG(bgp->flags, BGP_FLAG_LU_IPV6_EXPLICIT_NULL);

	return NB_OK;
}

void bgp_nb_cli_show_labeled_unicast_explicit_null(struct vty *vty, const struct lyd_node *dnode,
						   bool show_defaults)
{
	const char *val = yang_dnode_get_string(dnode, NULL);

	if (strmatch(val, "none")) {
		if (show_defaults)
			vty_out(vty, " no bgp labeled-unicast explicit-null\n");
		return;
	}

	vty_out(vty, " bgp labeled-unicast %s\n", val);
}

int bgp_nb_default_dynamic_capability_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_DYNAMIC_CAPABILITY);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_DYNAMIC_CAPABILITY);
	return NB_OK;
}

void bgp_nb_cli_show_default_dynamic_capability(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp default dynamic-capability\n");
	else if (show_defaults)
		vty_out(vty, " no bgp default dynamic-capability\n");
}

int bgp_nb_default_link_local_capability_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_LINK_LOCAL_CAPABILITY);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_LINK_LOCAL_CAPABILITY);
	return NB_OK;
}

void bgp_nb_cli_show_default_link_local_capability(struct vty *vty, const struct lyd_node *dnode,
						   bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp default link-local-capability\n");
	else if (show_defaults)
		vty_out(vty, " no bgp default link-local-capability\n");
}

int bgp_nb_default_software_version_capability_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *val;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	val = yang_dnode_get_string(args->dnode, NULL);

	UNSET_FLAG(bgp->flags,
		   BGP_FLAG_SOFT_VERSION_CAPABILITY_OLD | BGP_FLAG_SOFT_VERSION_CAPABILITY_NEW);

	if (strmatch(val, "old-encoding"))
		SET_FLAG(bgp->flags, BGP_FLAG_SOFT_VERSION_CAPABILITY_OLD);
	else if (strmatch(val, "latest-encoding"))
		SET_FLAG(bgp->flags, BGP_FLAG_SOFT_VERSION_CAPABILITY_NEW);

	return NB_OK;
}

void bgp_nb_cli_show_default_software_version_capability(struct vty *vty,
							 const struct lyd_node *dnode,
							 bool show_defaults)
{
	const char *val = yang_dnode_get_string(dnode, NULL);

	if (strmatch(val, "old-encoding"))
		vty_out(vty, " bgp default software-version-capability\n");
	else if (strmatch(val, "latest-encoding"))
		vty_out(vty, " bgp default software-version-capability latest-encoding\n");
	else if (show_defaults)
		vty_out(vty, " no bgp default software-version-capability\n");
}

/*
 * Helpers for remote-as mapping
 */
static int bgp_nb_parse_as_type(const char *as_type_str, enum peer_asn_type *as_type, as_t *as,
				const struct lyd_node *dnode)
{
	*as = 0;

	if (strmatch(as_type_str, "internal")) {
		*as_type = AS_INTERNAL;
	} else if (strmatch(as_type_str, "external")) {
		*as_type = AS_EXTERNAL;
	} else if (strmatch(as_type_str, "auto")) {
		*as_type = AS_AUTO;
	} else if (strmatch(as_type_str, "as-specified")) {
		*as_type = AS_SPECIFIED;
		if (!yang_dnode_exists(dnode, "../remote-as"))
			return 1; /* AS value not present yet */
		*as = yang_dnode_get_uint32(dnode, "../remote-as");
	} else {
		return -1;
	}

	return 0;
}

static void bgp_nb_fix_confed_local_as(struct peer *peer, as_t as)
{
	if (as == 0 && CHECK_FLAG(peer->bgp->config, BGP_CONFIG_CONFEDERATION))
		peer->local_as = peer->bgp->as;
}

/*
 * Numbered neighbors
 */
int bgp_nb_neighbor_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	const char *remote_addr_str;
	union sockunion su;
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
		bgp = nb_running_get_entry(lyd_parent(args->dnode), NULL, true);
		remote_addr_str = yang_dnode_get_string(args->dnode, "./remote-address");
		if (str2sockunion(remote_addr_str, &su) < 0) {
			snprintfrr(args->errmsg, args->errmsg_len, "invalid neighbor address %s",
				   remote_addr_str);
			return NB_ERR_VALIDATION;
		}
		if (peer_address_self_check(bgp, &su)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "cannot configure the local system as neighbor");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = nb_running_get_entry(lyd_parent(args->dnode), NULL, true);
	remote_addr_str = yang_dnode_get_string(args->dnode, "./remote-address");
	if (str2sockunion(remote_addr_str, &su) < 0)
		return NB_ERR_VALIDATION;

	peer = peer_lookup(bgp, &su);
	if (!peer) {
		peer = peer_create(&su, NULL, bgp, bgp->as, 0, AS_UNSPECIFIED, NULL, true, NULL,
				   CONNECTION_OUTGOING);
		if (!peer)
			return NB_ERR_RESOURCE;
	}

	nb_running_set_entry(args->dnode, peer);
	return NB_OK;
}

int bgp_nb_neighbor_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer, *other;
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = nb_running_unset_entry(args->dnode);
	if (!peer)
		return NB_OK;

	if (peer_dynamic_neighbor(peer))
		return NB_ERR_INCONSISTENCY;

	bgp = peer->bgp;
	other = peer->doppelganger;

	if (CHECK_FLAG(peer->flags, PEER_FLAG_CAPABILITY_ENHE) || peer->ifp)
		bgp_zebra_terminate_radv(bgp, peer);

	peer_notify_unconfig(peer->connection);
	peer_delete(peer);

	if (other && other->connection->status != Deleted) {
		peer_notify_unconfig(other->connection);
		peer_delete(other);
	}

	bgp_nb_may_stop_listening(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_neighbor(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* remote-as printed by child leaf cli_show */
}

void bgp_nb_cli_show_neighbor_end(struct vty *vty, const struct lyd_node *dnode)
{
}

int bgp_nb_neighbor_remote_as_type_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	const char *as_type_str;
	enum peer_asn_type as_type;
	as_t as = 0;
	int ret;
	const char *as_pretty;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = nb_running_get_entry(args->dnode, NULL, true);
	as_type_str = yang_dnode_get_string(args->dnode, NULL);
	as_pretty = as_type_str;

	ret = bgp_nb_parse_as_type(as_type_str, &as_type, &as, args->dnode);
	if (ret < 0)
		return NB_ERR_VALIDATION;
	if (ret > 0)
		return NB_OK; /* as-specified without remote-as yet */

	if (as_type == AS_SPECIFIED)
		as_pretty = yang_dnode_get_string(args->dnode, "../remote-as");

	peer_as_change(peer, as, as_type, as_pretty);
	SET_FLAG(peer->flags_override, PEER_FLAG_REMOTE_AS);
	bgp_nb_fix_confed_local_as(peer, as);
	bgp_nb_need_listening(peer->bgp);
	return NB_OK;
}

int bgp_nb_neighbor_remote_as_type_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = nb_running_get_entry(args->dnode, NULL, false);
	if (!peer)
		return NB_OK;

	peer_as_change(peer, 0, AS_UNSPECIFIED, NULL);
	UNSET_FLAG(peer->flags_override, PEER_FLAG_REMOTE_AS);
	return NB_OK;
}

void bgp_nb_cli_show_neighbor_remote_as_type(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults)
{
	const struct lyd_node *parent;
	const char *name = NULL;
	const char *type = yang_dnode_get_string(dnode, NULL);
	bool v6only;

	parent = yang_dnode_get_parent(dnode, "neighbor");
	if (parent)
		name = yang_dnode_get_string(parent, "./remote-address");
	else {
		parent = yang_dnode_get_parent(dnode, "unnumbered-neighbor");
		if (parent) {
			/* Combined line printed by peer-group cli_show. */
			if (yang_dnode_exists(parent, "./peer-group"))
				return;
			name = yang_dnode_get_string(parent, "./interface");
			v6only = yang_dnode_exists(parent, "./v6only") &&
				 yang_dnode_get_bool(parent, "./v6only");
			if (strmatch(type, "as-specified")) {
				if (!yang_dnode_exists(dnode, "../remote-as"))
					return;
				vty_out(vty, " neighbor %s interface%s remote-as %s\n", name,
					v6only ? " v6only" : "",
					yang_dnode_get_string(dnode, "../remote-as"));
			} else if (strmatch(type, "internal"))
				vty_out(vty, " neighbor %s interface%s remote-as internal\n", name,
					v6only ? " v6only" : "");
			else if (strmatch(type, "external"))
				vty_out(vty, " neighbor %s interface%s remote-as external\n", name,
					v6only ? " v6only" : "");
			else if (strmatch(type, "auto"))
				vty_out(vty, " neighbor %s interface%s remote-as auto\n", name,
					v6only ? " v6only" : "");
			return;
		}
	}
	if (!name)
		return;

	if (strmatch(type, "as-specified")) {
		if (!yang_dnode_exists(dnode, "../remote-as"))
			return;
		vty_out(vty, " neighbor %s remote-as %s\n", name,
			yang_dnode_get_string(dnode, "../remote-as"));
	} else if (strmatch(type, "internal"))
		vty_out(vty, " neighbor %s remote-as internal\n", name);
	else if (strmatch(type, "external"))
		vty_out(vty, " neighbor %s remote-as external\n", name);
	else if (strmatch(type, "auto"))
		vty_out(vty, " neighbor %s remote-as auto\n", name);
}

int bgp_nb_neighbor_remote_as_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	as_t as;
	const char *as_str;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = nb_running_get_entry(args->dnode, NULL, true);
	as = yang_dnode_get_uint32(args->dnode, NULL);
	as_str = yang_dnode_get_string(args->dnode, NULL);

	peer_as_change(peer, as, AS_SPECIFIED, as_str);
	SET_FLAG(peer->flags_override, PEER_FLAG_REMOTE_AS);
	bgp_nb_need_listening(peer->bgp);
	return NB_OK;
}

int bgp_nb_neighbor_remote_as_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

/*
 * Peer-groups
 */
int bgp_nb_peer_group_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	const char *name;
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
		bgp = nb_running_get_entry(lyd_parent(args->dnode), NULL, true);
		name = yang_dnode_get_string(args->dnode, "./peer-group-name");
		if (peer_lookup_by_conf_if(bgp, name)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "name conflict with interface peer");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = nb_running_get_entry(lyd_parent(args->dnode), NULL, true);
	name = yang_dnode_get_string(args->dnode, "./peer-group-name");

	group = peer_group_get(bgp, name);
	if (!group)
		return NB_ERR_RESOURCE;

	nb_running_set_entry(args->dnode, group);
	return NB_OK;
}

int bgp_nb_peer_group_destroy(struct nb_cb_destroy_args *args)
{
	struct peer_group *group;
	struct bgp *bgp;
	afi_t afi;

	switch (args->event) {
	case NB_EV_VALIDATE:
		group = nb_running_get_entry(args->dnode, NULL, false);
		if (!group)
			return NB_OK;
		for (afi = AFI_IP; afi < AFI_MAX; afi++) {
			if (listcount(group->listen_range[afi])) {
				snprintfrr(args->errmsg, args->errmsg_len,
					   "peer-group %s still has listen-range(s)", group->name);
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

	group = nb_running_unset_entry(args->dnode);
	if (!group)
		return NB_OK;

	bgp = group->bgp;
	peer_group_notify_unconfig(group);
	peer_group_delete(group);
	bgp_nb_may_stop_listening(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_peer_group(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, " neighbor %s peer-group\n",
		yang_dnode_get_string(dnode, "./peer-group-name"));
}

void bgp_nb_cli_show_peer_group_end(struct vty *vty, const struct lyd_node *dnode)
{
}

int bgp_nb_peer_group_remote_as_type_modify(struct nb_cb_modify_args *args)
{
	struct peer_group *group;
	struct bgp *bgp;
	const char *as_type_str;
	enum peer_asn_type as_type;
	as_t as = 0;
	int ret;
	const char *as_pretty;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	group = nb_running_get_entry(args->dnode, NULL, true);
	bgp = group->bgp;
	as_type_str = yang_dnode_get_string(args->dnode, NULL);
	as_pretty = as_type_str;

	ret = bgp_nb_parse_as_type(as_type_str, &as_type, &as, args->dnode);
	if (ret < 0)
		return NB_ERR_VALIDATION;
	if (ret > 0)
		return NB_OK;

	if (as_type == AS_SPECIFIED)
		as_pretty = yang_dnode_get_string(args->dnode, "../remote-as");

	ret = peer_group_remote_as(bgp, group->name, &as, as_type, as_pretty);
	if (ret != 0)
		return NB_ERR_RESOURCE;

	if (as == 0 && CHECK_FLAG(bgp->config, BGP_CONFIG_CONFEDERATION)) {
		struct listnode *node;
		struct peer *peer;

		group->conf->local_as = bgp->as;
		for (ALL_LIST_ELEMENTS_RO(group->peer, node, peer))
			peer->local_as = bgp->as;
	}

	bgp_nb_need_listening(bgp);
	return NB_OK;
}

int bgp_nb_peer_group_remote_as_type_destroy(struct nb_cb_destroy_args *args)
{
	struct peer_group *group;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	group = nb_running_get_entry(args->dnode, NULL, true);
	if (!group)
		return NB_OK;

	peer_group_remote_as_delete(group);
	return NB_OK;
}

void bgp_nb_cli_show_peer_group_remote_as_type(struct vty *vty, const struct lyd_node *dnode,
					       bool show_defaults)
{
	const char *name = yang_dnode_get_string(dnode, "../../peer-group-name");
	const char *type = yang_dnode_get_string(dnode, NULL);

	if (strmatch(type, "as-specified")) {
		if (!yang_dnode_exists(dnode, "../remote-as"))
			return;
		vty_out(vty, " neighbor %s remote-as %s\n", name,
			yang_dnode_get_string(dnode, "../remote-as"));
	} else if (strmatch(type, "internal"))
		vty_out(vty, " neighbor %s remote-as internal\n", name);
	else if (strmatch(type, "external"))
		vty_out(vty, " neighbor %s remote-as external\n", name);
	else if (strmatch(type, "auto"))
		vty_out(vty, " neighbor %s remote-as auto\n", name);
}

int bgp_nb_peer_group_remote_as_modify(struct nb_cb_modify_args *args)
{
	struct peer_group *group;
	as_t as;
	const char *as_str;
	int ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	group = nb_running_get_entry(args->dnode, NULL, true);
	as = yang_dnode_get_uint32(args->dnode, NULL);
	as_str = yang_dnode_get_string(args->dnode, NULL);

	ret = peer_group_remote_as(group->bgp, group->name, &as, AS_SPECIFIED, as_str);
	if (ret != 0)
		return NB_ERR_RESOURCE;

	bgp_nb_need_listening(group->bgp);
	return NB_OK;
}

int bgp_nb_peer_group_remote_as_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

/*
 * Resolve config peer from neighbor, unnumbered-neighbor, or peer-group.
 */
static struct peer *bgp_nb_config_peer(const struct lyd_node *dnode)
{
	const struct lyd_node *list;
	struct peer_group *group;

	list = yang_dnode_get_parent(dnode, "neighbor");
	if (list)
		return nb_running_get_entry(list, NULL, true);

	list = yang_dnode_get_parent(dnode, "unnumbered-neighbor");
	if (list)
		return nb_running_get_entry(list, NULL, true);

	list = yang_dnode_get_parent(dnode, "peer-group");
	if (list) {
		group = nb_running_get_entry(list, NULL, true);
		return group ? group->conf : NULL;
	}

	return NULL;
}

static const char *bgp_nb_config_peer_name(const struct lyd_node *dnode)
{
	const struct lyd_node *list;

	list = yang_dnode_get_parent(dnode, "neighbor");
	if (list)
		return yang_dnode_get_string(list, "./remote-address");

	list = yang_dnode_get_parent(dnode, "unnumbered-neighbor");
	if (list)
		return yang_dnode_get_string(list, "./interface");

	list = yang_dnode_get_parent(dnode, "peer-group");
	if (list)
		return yang_dnode_get_string(list, "./peer-group-name");

	return "?";
}

/*
 * Unnumbered neighbors
 */
int bgp_nb_unnumbered_neighbor_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	const char *ifname;
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
		bgp = nb_running_get_entry(lyd_parent(args->dnode), NULL, true);
		ifname = yang_dnode_get_string(args->dnode, "./interface");
		if (peer_group_lookup(bgp, ifname)) {
			snprintfrr(args->errmsg, args->errmsg_len, "name conflict with peer-group");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = nb_running_get_entry(lyd_parent(args->dnode), NULL, true);
	ifname = yang_dnode_get_string(args->dnode, "./interface");

	peer = peer_lookup_by_conf_if(bgp, ifname);
	if (!peer) {
		peer = peer_create(NULL, ifname, bgp, bgp->as, 0, AS_UNSPECIFIED, NULL, true, NULL,
				   CONNECTION_OUTGOING);
		if (!peer)
			return NB_ERR_RESOURCE;

		bgp_zebra_initiate_radv(bgp, peer);

		if (!CHECK_FLAG(peer->flags_invert, PEER_FLAG_CAPABILITY_ENHE)) {
			SET_FLAG(peer->flags, PEER_FLAG_CAPABILITY_ENHE);
			SET_FLAG(peer->flags_invert, PEER_FLAG_CAPABILITY_ENHE);
			SET_FLAG(peer->flags_override, PEER_FLAG_CAPABILITY_ENHE);
		}
	}

	nb_running_set_entry(args->dnode, peer);
	bgp_nb_need_listening(bgp);
	return NB_OK;
}

int bgp_nb_unnumbered_neighbor_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer, *other;
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = nb_running_unset_entry(args->dnode);
	if (!peer)
		return NB_OK;

	bgp = peer->bgp;
	other = peer->doppelganger;
	if (peer->ifp || CHECK_FLAG(peer->flags, PEER_FLAG_CAPABILITY_ENHE))
		bgp_zebra_terminate_radv(bgp, peer);
	peer_notify_unconfig(peer->connection);
	peer_delete(peer);
	if (other && other->connection->status != Deleted) {
		peer_notify_unconfig(other->connection);
		peer_delete(other);
	}
	bgp_nb_may_stop_listening(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_unnumbered_neighbor(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults)
{
	const char *ifname = yang_dnode_get_string(dnode, "./interface");
	bool v6only = yang_dnode_exists(dnode, "./v6only") &&
		      yang_dnode_get_bool(dnode, "./v6only");

	/*
	 * Full line (v6only / peer-group / remote-as) is composed from child
	 * cli_show callbacks; emit the base create form when nothing else
	 * prints a complete interface line. Prefer printing here only the
	 * bare interface create when no remote-as is present.
	 */
	if (!yang_dnode_exists(dnode, "./neighbor-remote-as/remote-as-type") &&
	    !yang_dnode_exists(dnode, "./peer-group")) {
		if (v6only)
			vty_out(vty, " neighbor %s interface v6only\n", ifname);
		else
			vty_out(vty, " neighbor %s interface\n", ifname);
	}
}

void bgp_nb_cli_show_unnumbered_neighbor_end(struct vty *vty, const struct lyd_node *dnode)
{
}

int bgp_nb_unnumbered_v6only_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	bool v6only;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = nb_running_get_entry(args->dnode, NULL, true);
	v6only = yang_dnode_get_bool(args->dnode, NULL);

	if (v6only == !!CHECK_FLAG(peer->flags, PEER_FLAG_IFPEER_V6ONLY))
		return NB_OK;

	if (v6only)
		peer_flag_set(peer, PEER_FLAG_IFPEER_V6ONLY);
	else
		peer_flag_unset(peer, PEER_FLAG_IFPEER_V6ONLY);

	peer_set_last_reset(peer, PEER_DOWN_V6ONLY_CHANGE);
	if (!peer_notify_config_change(peer->connection))
		bgp_session_reset(peer);

	return NB_OK;
}

void bgp_nb_cli_show_unnumbered_v6only(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults)
{
	/* Printed with interface / peer-group / remote-as composition. */
}

int bgp_nb_unnumbered_peer_group_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	struct peer_group *group;
	const char *group_name;
	as_t as;
	int ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = nb_running_get_entry(args->dnode, NULL, true);
	group_name = yang_dnode_get_string(args->dnode, NULL);
	group = peer_group_lookup(peer->bgp, group_name);
	if (!group)
		return NB_ERR_NOT_FOUND;

	as = peer->as;
	ret = peer_group_bind(peer->bgp, NULL, peer, group, &as);
	if (ret != 0)
		return NB_ERR_RESOURCE;

	return NB_OK;
}

int bgp_nb_unnumbered_peer_group_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = nb_running_get_entry(args->dnode, NULL, true);
	if (!peer || !peer->group)
		return NB_OK;

	if (peer_group_unbind(peer->bgp, peer, peer->group) != 0)
		return NB_ERR_RESOURCE;

	return NB_OK;
}

void bgp_nb_cli_show_unnumbered_peer_group(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	const char *ifname = yang_dnode_get_string(dnode, "../interface");
	const char *pg = yang_dnode_get_string(dnode, NULL);
	bool v6only = yang_dnode_exists(dnode, "../v6only") &&
		      yang_dnode_get_bool(dnode, "../v6only");
	const char *type = NULL;

	if (yang_dnode_exists(dnode, "../neighbor-remote-as/remote-as-type"))
		type = yang_dnode_get_string(dnode, "../neighbor-remote-as/remote-as-type");

	/*
	 * Prefer a single combined line when peer-group is set. Remote-as
	 * child cli_show also prints; suppress bare remote-as when we print
	 * here with peer-group. Simpler: print interface+v6only+peer-group
	 * and let remote-as cli_show print remote-as separately (classic
	 * write often splits). Match classic: one line with all options.
	 */
	vty_out(vty, " neighbor %s interface%s peer-group %s", ifname, v6only ? " v6only" : "", pg);
	if (type) {
		if (strmatch(type, "as-specified") &&
		    yang_dnode_exists(dnode, "../neighbor-remote-as/remote-as"))
			vty_out(vty, " remote-as %s",
				yang_dnode_get_string(dnode, "../neighbor-remote-as/remote-as"));
		else if (strmatch(type, "internal"))
			vty_out(vty, " remote-as internal");
		else if (strmatch(type, "external"))
			vty_out(vty, " remote-as external");
		else if (strmatch(type, "auto"))
			vty_out(vty, " remote-as auto");
	}
	vty_out(vty, "\n");
}

/*
 * Shared session leaves
 */
int bgp_nb_peer_password_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	int ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	ret = peer_password_set(peer, yang_dnode_get_string(args->dnode, NULL));
	return ret ? NB_ERR_RESOURCE : NB_OK;
}

int bgp_nb_peer_password_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_OK;

	peer_password_unset(peer);
	return NB_OK;
}

void bgp_nb_cli_show_peer_password(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults)
{
	vty_out(vty, " neighbor %s password %s\n", bgp_nb_config_peer_name(dnode),
		yang_dnode_get_string(dnode, NULL));
}

int bgp_nb_peer_description_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	peer_description_set(peer, yang_dnode_get_string(args->dnode, NULL));
	return NB_OK;
}

int bgp_nb_peer_description_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_OK;

	peer_description_unset(peer);
	return NB_OK;
}

void bgp_nb_cli_show_peer_description(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults)
{
	vty_out(vty, " neighbor %s description %s\n", bgp_nb_config_peer_name(dnode),
		yang_dnode_get_string(dnode, NULL));
}

int bgp_nb_peer_passive_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_flag_set(peer, PEER_FLAG_PASSIVE);
	else
		peer_flag_unset(peer, PEER_FLAG_PASSIVE);
	return NB_OK;
}

void bgp_nb_cli_show_peer_passive(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s passive\n", bgp_nb_config_peer_name(dnode));
	else if (show_defaults)
		vty_out(vty, " no neighbor %s passive\n", bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_solo_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	update_group_adjust_soloness(peer, yang_dnode_get_bool(args->dnode, NULL));
	return NB_OK;
}

void bgp_nb_cli_show_peer_solo(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s solo\n", bgp_nb_config_peer_name(dnode));
	else if (show_defaults)
		vty_out(vty, " no neighbor %s solo\n", bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_shutdown_enable_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_flag_set(peer, PEER_FLAG_SHUTDOWN);
	else {
		peer_tx_shutdown_message_unset(peer);
		peer_flag_unset(peer, PEER_FLAG_SHUTDOWN);
	}
	return NB_OK;
}

void bgp_nb_cli_show_peer_shutdown_enable(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults)
{
	const struct lyd_node *shut = yang_dnode_get_parent(dnode, "admin-shutdown");

	/* Message leaf prints the combined form when present. */
	if (shut && yang_dnode_exists(shut, "./message"))
		return;

	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s shutdown\n", bgp_nb_config_peer_name(dnode));
	else if (show_defaults)
		vty_out(vty, " no neighbor %s shutdown\n", bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_shutdown_message_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	peer_tx_shutdown_message_set(peer, yang_dnode_get_string(args->dnode, NULL));
	return NB_OK;
}

int bgp_nb_peer_shutdown_message_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_OK;

	peer_tx_shutdown_message_unset(peer);
	return NB_OK;
}

void bgp_nb_cli_show_peer_shutdown_message(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	vty_out(vty, " neighbor %s shutdown message %s\n", bgp_nb_config_peer_name(dnode),
		yang_dnode_get_string(dnode, NULL));
}
