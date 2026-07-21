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
#include "bgpd/bgp_open.h"
#include "bgpd/bgp_updgrp.h"
#include "bgpd/bgp_bfd.h"
#include "routemap.h"
#include "filter.h"
#include "bfd.h"
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
	struct in_addr router_id;

	yang_dnode_get_ipv4(&router_id, dnode, NULL);
	if (router_id.s_addr == INADDR_ANY)
		return;
	vty_out(vty, " bgp router-id %pI4\n", &router_id);
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
	if (CHECK_FLAG(bgp->config, BGP_CONFIG_CLUSTER_ID) &&
	    IPV4_ADDR_SAME(&bgp->cluster_id, &cluster))
		return NB_OK;
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
	struct in_addr cluster;

	if (inet_aton(yang_dnode_get_string(dnode, NULL), &cluster))
		vty_out(vty, " bgp cluster-id %pI4\n", &cluster);
	else
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

int bgp_nb_prefer_mpls_over_srv6_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	bool enable;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	enable = yang_dnode_get_bool(args->dnode, NULL);
	if (enable == !!CHECK_FLAG(bgp->flags, BGP_FLAG_BESTPATH_PREFER_MPLS_OVER_SRV6))
		return NB_OK;
	if (enable)
		SET_FLAG(bgp->flags, BGP_FLAG_BESTPATH_PREFER_MPLS_OVER_SRV6);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_BESTPATH_PREFER_MPLS_OVER_SRV6);
	bgp_recalculate_all_bestpaths(bgp);
	return NB_OK;
}

void bgp_nb_cli_show_prefer_mpls_over_srv6(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp bestpath prefer-mpls-over-srv6\n");
	else if (show_defaults)
		vty_out(vty, " no bgp bestpath prefer-mpls-over-srv6\n");
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
	bool enable;
	bool was_enabled;
	bool had_as_set;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	enable = yang_dnode_get_bool(args->dnode, NULL);
	was_enabled = CHECK_FLAG(bgp->flags, BGP_FLAG_ASPATH_MULTIPATH_RELAX);
	had_as_set = CHECK_FLAG(bgp->flags, BGP_FLAG_MULTIPATH_RELAX_AS_SET);

	if (enable) {
		if (was_enabled)
			return NB_OK;
		SET_FLAG(bgp->flags, BGP_FLAG_ASPATH_MULTIPATH_RELAX);
	} else {
		if (!was_enabled && !had_as_set)
			return NB_OK;
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
	bool enable;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	enable = yang_dnode_get_bool(args->dnode, NULL);
	if (enable == !!CHECK_FLAG(bgp->flags, BGP_FLAG_MULTIPATH_RELAX_AS_SET))
		return NB_OK;

	if (enable)
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
				   "hold time value must be either 0 or at least 3");
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
	const struct lyd_node *confed;
	const char *pretty;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	confed = yang_dnode_get_parent(args->dnode, "confederation");
	pretty = (confed && yang_dnode_exists(confed, "identifier-pretty"))
			 ? yang_dnode_get_string(confed, "identifier-pretty")
			 : yang_dnode_get_string(args->dnode, NULL);
	bgp_confederation_id_set(bgp, yang_dnode_get_uint32(args->dnode, NULL), pretty);
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

int bgp_nb_confederation_identifier_pretty_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *pretty;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp->confed_id)
		return NB_OK;
	pretty = yang_dnode_get_string(args->dnode, NULL);
	if (bgp->confed_id_pretty && strmatch(bgp->confed_id_pretty, pretty))
		return NB_OK;
	XFREE(MTYPE_BGP_NAME, bgp->confed_id_pretty);
	bgp->confed_id_pretty = XSTRDUP(MTYPE_BGP_NAME, pretty);
	return NB_OK;
}

int bgp_nb_confederation_identifier_pretty_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!bgp->confed_id)
		return NB_OK;
	XFREE(MTYPE_BGP_NAME, bgp->confed_id_pretty);
	bgp->confed_id_pretty = XSTRDUP(MTYPE_BGP_NAME, asn_asn2asplain(bgp->confed_id));
	return NB_OK;
}

void bgp_nb_cli_show_confederation_identifier(struct vty *vty, const struct lyd_node *dnode,
					      bool show_defaults)
{
	const struct lyd_node *confed = yang_dnode_get_parent(dnode, "confederation");
	const char *pretty = (confed && yang_dnode_exists(confed, "identifier-pretty"))
				     ? yang_dnode_get_string(confed, "identifier-pretty")
				     : yang_dnode_get_string(dnode, NULL);

	vty_out(vty, " bgp confederation identifier %s\n", pretty);
}

int bgp_nb_confederation_member_as_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	const struct lyd_node *confed;
	as_t as;
	char xpath[96];
	const char *pretty;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	as = yang_dnode_get_uint32(args->dnode, NULL);
	confed = yang_dnode_get_parent(args->dnode, "confederation");
	snprintfrr(xpath, sizeof(xpath), "./member-as-pretty[as='%u']/as-pretty", as);
	pretty = (confed && yang_dnode_exists(confed, xpath))
			 ? yang_dnode_get_string(confed, "./member-as-pretty[as='%u']/as-pretty",
						 as)
			 : yang_dnode_get_string(args->dnode, NULL);
	bgp_confederation_peers_add(bgp, as, pretty);
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

int bgp_nb_confederation_member_as_pretty_create(struct nb_cb_create_args *args)
{
	return NB_OK;
}

int bgp_nb_confederation_member_as_pretty_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

int bgp_nb_confederation_member_as_pretty_val_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	as_t as;
	const char *pretty;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	as = yang_dnode_get_uint32(args->dnode, "../as");
	pretty = yang_dnode_get_string(args->dnode, NULL);
	for (int i = 0; i < bgp->confed_peers_cnt; i++) {
		if (bgp->confed_peers[i].as != as)
			continue;
		if (bgp->confed_peers[i].as_pretty &&
		    strmatch(bgp->confed_peers[i].as_pretty, pretty))
			break;
		XFREE(MTYPE_BGP_NAME, bgp->confed_peers[i].as_pretty);
		bgp->confed_peers[i].as_pretty = XSTRDUP(MTYPE_BGP_NAME, pretty);
		break;
	}
	return NB_OK;
}

void bgp_nb_cli_show_confederation_member_as(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults)
{
	const struct lyd_node *confed = yang_dnode_get_parent(dnode, "confederation");
	const struct lyd_node *child;
	char xpath[96];

	if (!confed)
		return;

	/* Emit all confederation peers on a single line from the first entry. */
	LY_LIST_FOR (lyd_child(confed), child) {
		if (strmatch(child->schema->name, "member-as"))
			break;
	}
	if (child != dnode)
		return;

	vty_out(vty, " bgp confederation peers");
	LY_LIST_FOR (lyd_child(confed), child) {
		as_t as;
		const char *pretty;

		if (!strmatch(child->schema->name, "member-as"))
			continue;
		as = yang_dnode_get_uint32(child, NULL);
		snprintfrr(xpath, sizeof(xpath), "./member-as-pretty[as='%u']/as-pretty", as);
		pretty = yang_dnode_exists(confed, xpath)
				 ? yang_dnode_get_string(confed,
							 "./member-as-pretty[as='%u']/as-pretty",
							 as)
				 : yang_dnode_get_string(child, NULL);
		vty_out(vty, " %s", pretty);
	}
	vty_out(vty, "\n");
}

int bgp_nb_enable_med_admin_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const struct lyd_node *med;
	uint32_t value;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (yang_dnode_get_bool(args->dnode, NULL)) {
		med = yang_dnode_get_parent(args->dnode, "med-config");
		value = (med && yang_dnode_exists(med, "max-med-admin"))
				? yang_dnode_get_uint32(med, "max-med-admin")
				: BGP_MAXMED_VALUE_DEFAULT;
		bgp->v_maxmed_admin = 1;
		bgp->maxmed_admin_value = value;
	} else {
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
	uint32_t value;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	med = yang_dnode_get_parent(args->dnode, "med-config");
	if (!yang_dnode_get_bool(med, "enable-med-admin"))
		return NB_OK;

	value = yang_dnode_get_uint32(args->dnode, NULL);
	if (bgp->v_maxmed_admin == 1 && bgp->maxmed_admin_value == value)
		return NB_OK;

	bgp->maxmed_admin_value = value;
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
	case NB_EV_VALIDATE: {
		const char *conflict = NULL;

		if (afi == AFI_IP && safi == SAFI_UNICAST)
			conflict = "../default-afi-safi[.='ipv4-labeled-unicast']";
		else if (afi == AFI_IP && safi == SAFI_LABELED_UNICAST)
			conflict = "../default-afi-safi[.='ipv4-unicast']";
		else if (afi == AFI_IP6 && safi == SAFI_UNICAST)
			conflict = "../default-afi-safi[.='ipv6-labeled-unicast']";
		else if (afi == AFI_IP6 && safi == SAFI_LABELED_UNICAST)
			conflict = "../default-afi-safi[.='ipv6-unicast']";

		if (conflict && yang_dnode_exists(args->dnode, conflict)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "Cannot activate both unicast and labeled-unicast by default");
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
	const char *afi_safi = yang_dnode_get_string(dnode, NULL);

	/*
	 * ipv4-unicast is seeded as the implicit C default on new instances.
	 * Omit from show running unless showing defaults (classic behavior).
	 */
	if (!show_defaults && strmatch(afi_safi, "ipv4-unicast"))
		return;

	vty_out(vty, " bgp default %s\n", afi_safi);
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
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (CHECK_FLAG(bgp->flags, BGP_FLAG_SHUTDOWN)) {
		if (yang_dnode_get_bool(args->dnode, NULL))
			SET_FLAG(bgp->flags, BGP_FLAG_SHUTDOWN_NO_NOTIFY);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_SHUTDOWN_NO_NOTIFY);
	}
	return NB_OK;
}

int bgp_nb_shutdown_no_notify_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	UNSET_FLAG(bgp->flags, BGP_FLAG_SHUTDOWN_NO_NOTIFY);
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
		/*
		 * peer_lookup() also returns dynamic peers from "bgp listen
		 * range". Binding the YANG node to one changes its AS, and
		 * the FSM frees that peer when the session drops.
		 */
		if (bgp) {
			peer = peer_lookup(bgp, &su);
			if (peer && peer_dynamic_neighbor(peer)) {
				snprintfrr(args->errmsg, args->errmsg_len,
					   "Operation not allowed on a dynamic neighbor");
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

	bgp = nb_running_get_entry(lyd_parent(args->dnode), NULL, true);
	remote_addr_str = yang_dnode_get_string(args->dnode, "./remote-address");
	if (str2sockunion(remote_addr_str, &su) < 0)
		return NB_ERR_VALIDATION;

	peer = peer_lookup(bgp, &su);
	if (peer && peer_dynamic_neighbor(peer)) {
		/* VALIDATE rejects this. Do not adopt the dynamic peer. */
		return NB_OK;
	}
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

	switch (args->event) {
	case NB_EV_VALIDATE:
		peer = nb_running_get_entry(args->dnode, NULL, false);
		if (peer && peer_dynamic_neighbor(peer)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "Operation not allowed on a dynamic neighbor");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = nb_running_get_entry(args->dnode, NULL, false);
	if (!peer)
		return NB_OK;

	/*
	 * VALIDATE rejects this. Leave the entry in place: unsetting it and
	 * then failing would drop the binding while the node stays configured.
	 */
	if (peer_dynamic_neighbor(peer))
		return NB_OK;

	nb_running_unset_entry(args->dnode);

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

static const char *bgp_nb_peer_show_indent(const struct lyd_node *dnode);

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
	vty_out(vty, "%sneighbor %s peer-group\n", bgp_nb_peer_show_indent(dnode),
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

/* Address-family neighbor lines are indented under the AF; router lines are not. */
static const char *bgp_nb_peer_show_indent(const struct lyd_node *dnode)
{
	if (yang_dnode_get_parent(dnode, "afi-safi"))
		return "  ";
	return " ";
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
			vty_out(vty, "%sneighbor %s interface v6only\n",
				bgp_nb_peer_show_indent(dnode), ifname);
		else
			vty_out(vty, "%sneighbor %s interface\n", bgp_nb_peer_show_indent(dnode),
				ifname);
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
	/*
	 * Same unbind as a numbered neighbor: drop the group, inherited
	 * config, and update-group membership. bgp_nb_config_peer()
	 * resolves an unnumbered-neighbor entry.
	 */
	return bgp_nb_neighbor_peer_group_destroy(args);
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
	vty_out(vty, "%sneighbor %s password %s\n", bgp_nb_peer_show_indent(dnode),
		bgp_nb_config_peer_name(dnode), yang_dnode_get_string(dnode, NULL));
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
	vty_out(vty, "%sneighbor %s description %s\n", bgp_nb_peer_show_indent(dnode),
		bgp_nb_config_peer_name(dnode), yang_dnode_get_string(dnode, NULL));
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
		vty_out(vty, "%sneighbor %s passive\n", bgp_nb_peer_show_indent(dnode),
			bgp_nb_config_peer_name(dnode));
	else if (show_defaults)
		vty_out(vty, "%sno neighbor %s passive\n", bgp_nb_peer_show_indent(dnode),
			bgp_nb_config_peer_name(dnode));
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
		vty_out(vty, "%sneighbor %s solo\n", bgp_nb_peer_show_indent(dnode),
			bgp_nb_config_peer_name(dnode));
	else if (show_defaults)
		vty_out(vty, "%sno neighbor %s solo\n", bgp_nb_peer_show_indent(dnode),
			bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_shutdown_enable_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	if (yang_dnode_get_bool(args->dnode, NULL)) {
		const struct lyd_node *shut;

		/*
		 * Schema order applies enable before message. The cease
		 * notification is sent from peer_flag_set(), so copy the
		 * message from the candidate first. Classic CLI does the
		 * same: peer_tx_shutdown_message_set() then the flag.
		 */
		shut = yang_dnode_get_parent(args->dnode, "admin-shutdown");
		if (shut && yang_dnode_exists(shut, "./message"))
			peer_tx_shutdown_message_set(peer,
						     yang_dnode_get_string(shut, "./message"));
		peer_flag_set(peer, PEER_FLAG_SHUTDOWN);
	} else {
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
		vty_out(vty, "%sneighbor %s shutdown\n", bgp_nb_peer_show_indent(dnode),
			bgp_nb_config_peer_name(dnode));
	else if (show_defaults)
		vty_out(vty, "%sno neighbor %s shutdown\n", bgp_nb_peer_show_indent(dnode),
			bgp_nb_config_peer_name(dnode));
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
	vty_out(vty, "%sneighbor %s shutdown message %s\n", bgp_nb_peer_show_indent(dnode),
		bgp_nb_config_peer_name(dnode), yang_dnode_get_string(dnode, NULL));
}

/*
 * Shared connection / timer / capability session leaves
 */
int bgp_nb_peer_update_source_ip_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	union sockunion su;
	const char *ip;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	ip = yang_dnode_get_string(args->dnode, NULL);
	if (str2sockunion(ip, &su) < 0)
		return NB_ERR_VALIDATION;

	peer_update_source_addr_set(peer, &su);
	return NB_OK;
}

int bgp_nb_peer_update_source_ip_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (peer)
		peer_update_source_unset(peer);
	return NB_OK;
}

void bgp_nb_cli_show_peer_update_source_ip(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	vty_out(vty, "%sneighbor %s update-source %s\n", bgp_nb_peer_show_indent(dnode),
		bgp_nb_config_peer_name(dnode), yang_dnode_get_string(dnode, NULL));
}

int bgp_nb_peer_update_source_if_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	if (peer_update_source_if_set(peer, yang_dnode_get_string(args->dnode, NULL)))
		return NB_ERR_RESOURCE;
	return NB_OK;
}

int bgp_nb_peer_update_source_if_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (peer)
		peer_update_source_unset(peer);
	return NB_OK;
}

void bgp_nb_cli_show_peer_update_source_if(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	vty_out(vty, "%sneighbor %s update-source %s\n", bgp_nb_peer_show_indent(dnode),
		bgp_nb_config_peer_name(dnode), yang_dnode_get_string(dnode, NULL));
}

int bgp_nb_peer_ebgp_mh_enabled_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
		peer = bgp_nb_config_peer(args->dnode);
		if (!peer)
			return NB_ERR_VALIDATION;
		if (peer->conf_if) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "ebgp-multihop not valid for interface peer");
			return NB_ERR_VALIDATION;
		}
		if (yang_dnode_get_bool(args->dnode, NULL) && peer_gtsm_configured(peer)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "ebgp-multihop and ttl-security are mutually exclusive");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_ebgp_multihop_set(peer, MAXTTL, true);
	else
		peer_ebgp_multihop_unset(peer, true);
	return NB_OK;
}

int bgp_nb_peer_ebgp_mh_enabled_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (peer)
		peer_ebgp_multihop_unset(peer, true);
	return NB_OK;
}

void bgp_nb_cli_show_peer_ebgp_mh_enabled(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults)
{
	const struct lyd_node *mh = yang_dnode_get_parent(dnode, "ebgp-multihop");

	if (mh && yang_dnode_exists(mh, "./multihop-ttl"))
		return;

	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "%sneighbor %s ebgp-multihop\n", bgp_nb_peer_show_indent(dnode),
			bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_ebgp_mh_ttl_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	uint8_t ttl;

	switch (args->event) {
	case NB_EV_VALIDATE:
		peer = bgp_nb_config_peer(args->dnode);
		if (!peer)
			return NB_ERR_VALIDATION;
		if (peer->conf_if) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "ebgp-multihop not valid for interface peer");
			return NB_ERR_VALIDATION;
		}
		if (peer_gtsm_configured(peer)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "ebgp-multihop and ttl-security are mutually exclusive");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	ttl = yang_dnode_get_uint8(args->dnode, NULL);
	peer_ebgp_multihop_set(peer, ttl, true);
	return NB_OK;
}

int bgp_nb_peer_ebgp_mh_ttl_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (peer)
		peer_ebgp_multihop_unset(peer, true);
	return NB_OK;
}

void bgp_nb_cli_show_peer_ebgp_mh_ttl(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults)
{
	vty_out(vty, "%sneighbor %s ebgp-multihop %u\n", bgp_nb_peer_show_indent(dnode),
		bgp_nb_config_peer_name(dnode), yang_dnode_get_uint8(dnode, NULL));
}

int bgp_nb_peer_disable_connected_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_flag_set(peer, PEER_FLAG_DISABLE_CONNECTED_CHECK);
	else
		peer_flag_unset(peer, PEER_FLAG_DISABLE_CONNECTED_CHECK);
	return NB_OK;
}

void bgp_nb_cli_show_peer_disable_connected(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "%sneighbor %s disable-connected-check\n",
			bgp_nb_peer_show_indent(dnode), bgp_nb_config_peer_name(dnode));
	else if (show_defaults)
		vty_out(vty, "%sno neighbor %s disable-connected-check\n",
			bgp_nb_peer_show_indent(dnode), bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_ttl_security_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	uint8_t hops;

	switch (args->event) {
	case NB_EV_VALIDATE:
		peer = bgp_nb_config_peer(args->dnode);
		if (!peer)
			return NB_ERR_VALIDATION;
		hops = yang_dnode_get_uint8(args->dnode, NULL);
		if (peer->conf_if && hops > 1) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "interface peer hops cannot exceed 1");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	if (peer_ttl_security_hops_set(peer, yang_dnode_get_uint8(args->dnode, NULL)))
		return NB_ERR_RESOURCE;
	return NB_OK;
}

int bgp_nb_peer_ttl_security_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (peer)
		peer_ttl_security_hops_unset(peer);
	return NB_OK;
}

void bgp_nb_cli_show_peer_ttl_security(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults)
{
	vty_out(vty, "%sneighbor %s ttl-security hops %u\n", bgp_nb_peer_show_indent(dnode),
		bgp_nb_config_peer_name(dnode), yang_dnode_get_uint8(dnode, NULL));
}

static void bgp_nb_peer_local_as_apply(struct peer *peer, const struct lyd_node *dnode)
{
	const struct lyd_node *las;
	as_t as;
	bool no_prepend = false, replace_as = false, dual_as = false;
	const char *as_str;

	las = yang_dnode_get_parent(dnode, "local-as");
	if (!las || !yang_dnode_exists(las, "./local-as"))
		return;

	as = yang_dnode_get_uint32(las, "./local-as");
	as_str = yang_dnode_get_string(las, "./local-as");
	if (yang_dnode_exists(las, "./no-prepend"))
		no_prepend = yang_dnode_get_bool(las, "./no-prepend");
	if (yang_dnode_exists(las, "./replace-as"))
		replace_as = yang_dnode_get_bool(las, "./replace-as");
	if (yang_dnode_exists(las, "./dual-as"))
		dual_as = yang_dnode_get_bool(las, "./dual-as");

	peer_local_as_set(peer, as, no_prepend, replace_as, dual_as, as_str);
}

int bgp_nb_peer_local_as_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	bgp_nb_peer_local_as_apply(peer, args->dnode);
	return NB_OK;
}

int bgp_nb_peer_local_as_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (peer)
		peer_local_as_unset(peer);
	return NB_OK;
}

void bgp_nb_cli_show_peer_local_as(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults)
{
	const struct lyd_node *las = yang_dnode_get_parent(dnode, "local-as");
	bool no_prepend = las && yang_dnode_exists(las, "./no-prepend") &&
			  yang_dnode_get_bool(las, "./no-prepend");
	bool replace_as = las && yang_dnode_exists(las, "./replace-as") &&
			  yang_dnode_get_bool(las, "./replace-as");
	bool dual_as = las && yang_dnode_exists(las, "./dual-as") &&
		       yang_dnode_get_bool(las, "./dual-as");

	vty_out(vty, " neighbor %s local-as %s", bgp_nb_config_peer_name(dnode),
		yang_dnode_get_string(dnode, NULL));
	if (no_prepend)
		vty_out(vty, " no-prepend");
	if (replace_as)
		vty_out(vty, " replace-as");
	if (dual_as)
		vty_out(vty, " dual-as");
	vty_out(vty, "\n");
}

int bgp_nb_peer_local_as_no_prepend_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	bgp_nb_peer_local_as_apply(peer, args->dnode);
	return NB_OK;
}

int bgp_nb_peer_local_as_replace_as_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	bgp_nb_peer_local_as_apply(peer, args->dnode);
	return NB_OK;
}

int bgp_nb_peer_local_as_dual_as_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	bgp_nb_peer_local_as_apply(peer, args->dnode);
	return NB_OK;
}

static bool bgp_nb_timer_leaf_implicit(const struct lyd_node *timers, const char *path)
{
	const struct lyd_node *leaf;

	if (!timers || !yang_dnode_exists(timers, path))
		return true;

	leaf = yang_dnode_get(timers, path);
	return CHECK_FLAG(leaf->flags, LYD_DEFAULT);
}

/*
 * "no neighbor X timers" deletes both leaves. They have YANG defaults, so
 * the diff arrives as MODIFY back to 60/180 with LYD_DEFAULT set. That is
 * not an explicit "timers 60 180", which must still override "timers bgp".
 */
static bool bgp_nb_peer_timers_implicit(const struct lyd_node *dnode)
{
	const struct lyd_node *timers = yang_dnode_get_parent(dnode, "timers");

	return bgp_nb_timer_leaf_implicit(timers, "./keepalive") &&
	       bgp_nb_timer_leaf_implicit(timers, "./hold-time");
}

static int bgp_nb_peer_timers_validate(const struct lyd_node *dnode, char *errmsg,
				       size_t errmsg_len)
{
	const struct lyd_node *timers;
	uint32_t holdtime;

	timers = yang_dnode_get_parent(dnode, "timers");
	if (!timers || !yang_dnode_exists(timers, "./hold-time"))
		return NB_OK;

	holdtime = yang_dnode_get_uint16(timers, "./hold-time");
	if (holdtime < 3 && holdtime != 0) {
		snprintfrr(errmsg, errmsg_len, "hold time value must be either 0 or at least 3");
		return NB_ERR_VALIDATION;
	}

	return NB_OK;
}

static int bgp_nb_peer_timers_apply(const struct lyd_node *dnode)
{
	struct peer *peer;
	const struct lyd_node *timers;
	uint32_t keepalive, holdtime;

	peer = bgp_nb_config_peer(dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	if (bgp_nb_peer_timers_implicit(dnode)) {
		peer_timers_unset(peer);
		return NB_OK;
	}

	timers = yang_dnode_get_parent(dnode, "timers");
	keepalive = yang_dnode_get_uint16(timers, "./keepalive");
	holdtime = yang_dnode_get_uint16(timers, "./hold-time");
	peer_timers_set(peer, keepalive, holdtime);
	return NB_OK;
}

int bgp_nb_peer_timers_keepalive_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		return bgp_nb_peer_timers_validate(args->dnode, args->errmsg, args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	return bgp_nb_peer_timers_apply(args->dnode);
}

int bgp_nb_peer_timers_keepalive_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (peer)
		peer_timers_unset(peer);
	return NB_OK;
}

void bgp_nb_cli_show_peer_timers_keepalive(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	const struct lyd_node *timers = yang_dnode_get_parent(dnode, "timers");
	uint16_t hold = 0;

	if (timers && yang_dnode_exists(timers, "./hold-time"))
		hold = yang_dnode_get_uint16(timers, "./hold-time");

	vty_out(vty, "%sneighbor %s timers %u %u\n", bgp_nb_peer_show_indent(dnode),
		bgp_nb_config_peer_name(dnode), yang_dnode_get_uint16(dnode, NULL), hold);
}

void bgp_nb_cli_show_peer_timers_holdtime(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults)
{
	const struct lyd_node *timers = yang_dnode_get_parent(dnode, "timers");
	const struct lyd_node *ka;
	uint16_t keepalive;

	/*
	 * Keepalive owns this line when nb_cli_show will visit it. A default
	 * keepalive is skipped, which dropped "neighbor A timers 60 <hold>".
	 */
	ka = (timers && yang_dnode_exists(timers, "./keepalive"))
		     ? yang_dnode_get(timers, "./keepalive")
		     : NULL;
	if (ka && (show_defaults || !yang_dnode_is_default(ka, NULL)))
		return;

	keepalive = ka ? yang_dnode_get_uint16(ka, NULL) : DFLT_BGP_KEEPALIVE;
	vty_out(vty, "%sneighbor %s timers %u %u\n", bgp_nb_peer_show_indent(dnode),
		bgp_nb_config_peer_name(dnode), keepalive, yang_dnode_get_uint16(dnode, NULL));
}

int bgp_nb_peer_timers_holdtime_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		return bgp_nb_peer_timers_validate(args->dnode, args->errmsg, args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	return bgp_nb_peer_timers_apply(args->dnode);
}

int bgp_nb_peer_timers_holdtime_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (peer)
		peer_timers_unset(peer);
	return NB_OK;
}

int bgp_nb_peer_timers_connect_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	peer_timers_connect_set(peer, yang_dnode_get_uint16(args->dnode, NULL));
	return NB_OK;
}

int bgp_nb_peer_timers_connect_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (peer)
		peer_timers_connect_unset(peer);
	return NB_OK;
}

void bgp_nb_cli_show_peer_timers_connect(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults)
{
	vty_out(vty, "%sneighbor %s timers connect %u\n", bgp_nb_peer_show_indent(dnode),
		bgp_nb_config_peer_name(dnode), yang_dnode_get_uint16(dnode, NULL));
}

int bgp_nb_peer_timers_delayopen_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	peer_timers_delayopen_set(peer, yang_dnode_get_uint16(args->dnode, NULL));
	return NB_OK;
}

int bgp_nb_peer_timers_delayopen_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (peer)
		peer_timers_delayopen_unset(peer);
	return NB_OK;
}

void bgp_nb_cli_show_peer_timers_delayopen(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	vty_out(vty, "%sneighbor %s timers delayopen %u\n", bgp_nb_peer_show_indent(dnode),
		bgp_nb_config_peer_name(dnode), yang_dnode_get_uint16(dnode, NULL));
}

int bgp_nb_peer_advertise_interval_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	peer_advertise_interval_set(peer, yang_dnode_get_uint16(args->dnode, NULL));
	return NB_OK;
}

int bgp_nb_peer_advertise_interval_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (peer)
		peer_advertise_interval_unset(peer);
	return NB_OK;
}

void bgp_nb_cli_show_peer_advertise_interval(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults)
{
	vty_out(vty, "%sneighbor %s advertisement-interval %u\n", bgp_nb_peer_show_indent(dnode),
		bgp_nb_config_peer_name(dnode), yang_dnode_get_uint16(dnode, NULL));
}

int bgp_nb_peer_cap_dynamic_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_flag_set(peer, PEER_FLAG_DYNAMIC_CAPABILITY);
	else
		peer_flag_unset(peer, PEER_FLAG_DYNAMIC_CAPABILITY);
	return NB_OK;
}

void bgp_nb_cli_show_peer_cap_dynamic(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "%sneighbor %s capability dynamic\n", bgp_nb_peer_show_indent(dnode),
			bgp_nb_config_peer_name(dnode));
	else if (show_defaults)
		vty_out(vty, "%sno neighbor %s capability dynamic\n",
			bgp_nb_peer_show_indent(dnode), bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_cap_enhe_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (!yang_dnode_get_bool(args->dnode, NULL) &&
		    yang_dnode_get_parent(args->dnode, "unnumbered-neighbor")) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "Peer %s cannot have capability extended-nexthop turned off",
				   bgp_nb_config_peer_name(args->dnode));
			return NB_ERR_VALIDATION;
		}
		peer = bgp_nb_config_peer(args->dnode);
		if (!yang_dnode_get_bool(args->dnode, NULL) && peer && peer->conf_if) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "Peer %s cannot have capability extended-nexthop turned off",
				   peer->host);
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_flag_set(peer, PEER_FLAG_CAPABILITY_ENHE);
	else
		peer_flag_unset(peer, PEER_FLAG_CAPABILITY_ENHE);
	return NB_OK;
}

void bgp_nb_cli_show_peer_cap_enhe(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "%sneighbor %s capability extended-nexthop\n",
			bgp_nb_peer_show_indent(dnode), bgp_nb_config_peer_name(dnode));
	else if (show_defaults)
		vty_out(vty, "%sno neighbor %s capability extended-nexthop\n",
			bgp_nb_peer_show_indent(dnode), bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_cap_negotiate_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	/* true => negotiate (clear DONT_CAPABILITY) */
	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_flag_unset(peer, PEER_FLAG_DONT_CAPABILITY);
	else
		peer_flag_set(peer, PEER_FLAG_DONT_CAPABILITY);
	return NB_OK;
}

void bgp_nb_cli_show_peer_cap_negotiate(struct vty *vty, const struct lyd_node *dnode,
					bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "%sneighbor %s dont-capability-negotiate\n",
			bgp_nb_peer_show_indent(dnode), bgp_nb_config_peer_name(dnode));
	else if (show_defaults)
		vty_out(vty, "%sno neighbor %s dont-capability-negotiate\n",
			bgp_nb_peer_show_indent(dnode), bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_cap_fqdn_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_flag_set(peer, PEER_FLAG_CAPABILITY_FQDN);
	else
		peer_flag_unset(peer, PEER_FLAG_CAPABILITY_FQDN);
	return NB_OK;
}

void bgp_nb_cli_show_peer_cap_fqdn(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s capability fqdn\n", bgp_nb_config_peer_name(dnode));
	else if (show_defaults)
		vty_out(vty, " no neighbor %s capability fqdn\n", bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_enforce_first_as_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_flag_set(peer, PEER_FLAG_ENFORCE_FIRST_AS);
	else
		peer_flag_unset(peer, PEER_FLAG_ENFORCE_FIRST_AS);
	return NB_OK;
}

void bgp_nb_cli_show_peer_enforce_first_as(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL)) {
		if (show_defaults)
			vty_out(vty, "%sneighbor %s enforce-first-as\n",
				bgp_nb_peer_show_indent(dnode), bgp_nb_config_peer_name(dnode));
	} else
		vty_out(vty, "%sno neighbor %s enforce-first-as\n", bgp_nb_peer_show_indent(dnode),
			bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_cap_soft_version_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	const char *val;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	val = yang_dnode_get_string(args->dnode, NULL);
	peer_flag_unset(peer, PEER_FLAG_CAPABILITY_SOFT_VERSION_OLD |
				      PEER_FLAG_CAPABILITY_SOFT_VERSION_NEW);
	if (strmatch(val, "old-encoding"))
		peer_flag_set(peer, PEER_FLAG_CAPABILITY_SOFT_VERSION_OLD);
	else if (strmatch(val, "latest-encoding"))
		peer_flag_set(peer, PEER_FLAG_CAPABILITY_SOFT_VERSION_NEW);
	return NB_OK;
}

void bgp_nb_cli_show_peer_cap_soft_version(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	const char *val = yang_dnode_get_string(dnode, NULL);

	if (strmatch(val, "old-encoding"))
		vty_out(vty, " neighbor %s capability software-version\n",
			bgp_nb_config_peer_name(dnode));
	else if (strmatch(val, "latest-encoding"))
		vty_out(vty, " neighbor %s capability software-version latest-encoding\n",
			bgp_nb_config_peer_name(dnode));
	else if (show_defaults)
		vty_out(vty, " no neighbor %s capability software-version\n",
			bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_cap_link_local_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_flag_set(peer, PEER_FLAG_CAPABILITY_LINK_LOCAL);
	else
		peer_flag_unset(peer, PEER_FLAG_CAPABILITY_LINK_LOCAL);
	return NB_OK;
}

void bgp_nb_cli_show_peer_cap_link_local(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "%sneighbor %s capability link-local\n",
			bgp_nb_peer_show_indent(dnode), bgp_nb_config_peer_name(dnode));
	else if (show_defaults)
		vty_out(vty, "%sno neighbor %s capability link-local\n",
			bgp_nb_peer_show_indent(dnode), bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_cap_override_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_flag_set(peer, PEER_FLAG_OVERRIDE_CAPABILITY);
	else
		peer_flag_unset(peer, PEER_FLAG_OVERRIDE_CAPABILITY);
	return NB_OK;
}

void bgp_nb_cli_show_peer_cap_override(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "%sneighbor %s override-capability\n", bgp_nb_peer_show_indent(dnode),
			bgp_nb_config_peer_name(dnode));
	else if (show_defaults)
		vty_out(vty, "%sno neighbor %s override-capability\n",
			bgp_nb_peer_show_indent(dnode), bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_cap_strict_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_flag_set(peer, PEER_FLAG_STRICT_CAP_MATCH);
	else
		peer_flag_unset(peer, PEER_FLAG_STRICT_CAP_MATCH);
	return NB_OK;
}

void bgp_nb_cli_show_peer_cap_strict(struct vty *vty, const struct lyd_node *dnode,
				     bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "%sneighbor %s strict-capability-match\n",
			bgp_nb_peer_show_indent(dnode), bgp_nb_config_peer_name(dnode));
	else if (show_defaults)
		vty_out(vty, "%sno neighbor %s strict-capability-match\n",
			bgp_nb_peer_show_indent(dnode), bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_tcp_mss_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	peer_tcp_mss_set(peer, yang_dnode_get_uint16(args->dnode, NULL));
	return NB_OK;
}

int bgp_nb_peer_tcp_mss_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (peer)
		peer_tcp_mss_unset(peer);
	return NB_OK;
}

void bgp_nb_cli_show_peer_tcp_mss(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, "%sneighbor %s tcp-mss %u\n", bgp_nb_peer_show_indent(dnode),
		bgp_nb_config_peer_name(dnode), yang_dnode_get_uint16(dnode, NULL));
}

int bgp_nb_peer_ip_transparent_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
		peer = bgp_nb_config_peer(args->dnode);
		if (!peer)
			return NB_ERR_VALIDATION;
		if (yang_dnode_get_bool(args->dnode, NULL) &&
		    !peergroup_flag_check(peer, PEER_FLAG_UPDATE_SOURCE)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "ip-transparent requires update-source");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_flag_set(peer, PEER_FLAG_IP_TRANSPARENT);
	else
		peer_flag_unset(peer, PEER_FLAG_IP_TRANSPARENT);
	return NB_OK;
}

void bgp_nb_cli_show_peer_ip_transparent(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "%sneighbor %s ip-transparent\n", bgp_nb_peer_show_indent(dnode),
			bgp_nb_config_peer_name(dnode));
	else if (show_defaults)
		vty_out(vty, "%sno neighbor %s ip-transparent\n", bgp_nb_peer_show_indent(dnode),
			bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_rpki_strict_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_flag_set(peer, PEER_FLAG_RPKI_STRICT);
	else
		peer_flag_unset(peer, PEER_FLAG_RPKI_STRICT);
	return NB_OK;
}

void bgp_nb_cli_show_peer_rpki_strict(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "%sneighbor %s rpki strict\n", bgp_nb_peer_show_indent(dnode),
			bgp_nb_config_peer_name(dnode));
	else if (show_defaults)
		vty_out(vty, "%sno neighbor %s rpki strict\n", bgp_nb_peer_show_indent(dnode),
			bgp_nb_config_peer_name(dnode));
}

static bool bgp_nb_role_from_str(const char *role_str, uint8_t *role)
{
	if (strmatch(role_str, "provider"))
		*role = ROLE_PROVIDER;
	else if (strmatch(role_str, "rs-server"))
		*role = ROLE_RS_SERVER;
	else if (strmatch(role_str, "rs-client"))
		*role = ROLE_RS_CLIENT;
	else if (strmatch(role_str, "customer"))
		*role = ROLE_CUSTOMER;
	else if (strmatch(role_str, "peer"))
		*role = ROLE_PEER;
	else
		return false;

	return true;
}

static enum bgp_peer_sort bgp_nb_candidate_peer_sort(const struct lyd_node *dnode)
{
	const struct lyd_node *nbr, *bgp_node;
	const char *as_type;
	as_t local_as, remote_as;

	nbr = yang_dnode_get_parent(dnode, "neighbor");
	if (!nbr)
		nbr = yang_dnode_get_parent(dnode, "unnumbered-neighbor");
	if (!nbr)
		nbr = yang_dnode_get_parent(dnode, "peer-group");
	if (!nbr || !yang_dnode_exists(nbr, "neighbor-remote-as/remote-as-type"))
		return BGP_PEER_INTERNAL;

	as_type = yang_dnode_get_string(nbr, "neighbor-remote-as/remote-as-type");
	if (strmatch(as_type, "internal"))
		return BGP_PEER_IBGP;
	if (strmatch(as_type, "external"))
		return BGP_PEER_EBGP;
	if (!strmatch(as_type, "as-specified") ||
	    !yang_dnode_exists(nbr, "neighbor-remote-as/remote-as"))
		return BGP_PEER_INTERNAL;

	remote_as = yang_dnode_get_uint32(nbr, "neighbor-remote-as/remote-as");
	bgp_node = yang_dnode_get_parent(dnode, "bgp");
	if (!bgp_node || !yang_dnode_exists(bgp_node, "global/local-as"))
		return BGP_PEER_INTERNAL;
	local_as = yang_dnode_get_uint32(bgp_node, "global/local-as");
	if (!local_as)
		return BGP_PEER_INTERNAL;

	return local_as == remote_as ? BGP_PEER_IBGP : BGP_PEER_EBGP;
}

static int bgp_nb_peer_local_role_validate(const struct lyd_node *dnode, char *errmsg,
					   size_t errmsg_len)
{
	enum bgp_peer_sort sort;
	bool group;

	group = yang_dnode_get_parent(dnode, "peer-group") != NULL;
	sort = bgp_nb_candidate_peer_sort(dnode);

	/*
	 * An untyped peer-group is allowed; members are checked when they
	 * are bound. A neighbor, or a group that is already iBGP, is not.
	 */
	if ((!group && sort != BGP_PEER_EBGP) || (group && sort == BGP_PEER_IBGP)) {
		snprintfrr(errmsg, errmsg_len, "External roles can be set only on eBGP session");
		return NB_ERR_VALIDATION;
	}

	return NB_OK;
}

static void bgp_nb_peer_local_role_apply(struct peer *peer, const struct lyd_node *dnode)
{
	const struct lyd_node *lr;
	const char *role_str;
	bool strict = false;
	uint8_t role;

	lr = yang_dnode_get_parent(dnode, "local-role");
	if (!lr || !yang_dnode_exists(lr, "./role"))
		return;

	role_str = yang_dnode_get_string(lr, "./role");
	if (!bgp_nb_role_from_str(role_str, &role))
		return;

	if (yang_dnode_exists(lr, "./strict-mode"))
		strict = yang_dnode_get_bool(lr, "./strict-mode");

	if (peer_role_set(peer, role, strict) != CMD_SUCCESS) {
		zlog_warn("%s: local-role rejected for peer %s", __func__, peer->host);
		return;
	}

	bgp_vty_role_update(peer, CAPABILITY_ACTION_SET);
}

int bgp_nb_peer_local_role_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
		return bgp_nb_peer_local_role_validate(args->dnode, args->errmsg, args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	bgp_nb_peer_local_role_apply(peer, args->dnode);
	return NB_OK;
}

int bgp_nb_peer_local_role_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_OK;

	peer_role_unset(peer);
	bgp_vty_role_update(peer, CAPABILITY_ACTION_UNSET);
	return NB_OK;
}

void bgp_nb_cli_show_peer_local_role(struct vty *vty, const struct lyd_node *dnode,
				     bool show_defaults)
{
	const struct lyd_node *lr = yang_dnode_get_parent(dnode, "local-role");
	bool strict = lr && yang_dnode_exists(lr, "./strict-mode") &&
		      yang_dnode_get_bool(lr, "./strict-mode");

	vty_out(vty, "%sneighbor %s local-role %s%s\n", bgp_nb_peer_show_indent(dnode),
		bgp_nb_config_peer_name(dnode), yang_dnode_get_string(dnode, NULL),
		strict ? " strict-mode" : "");
}

int bgp_nb_peer_local_role_strict_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
		return bgp_nb_peer_local_role_validate(args->dnode, args->errmsg, args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	bgp_nb_peer_local_role_apply(peer, args->dnode);
	return NB_OK;
}

static void bgp_nb_peer_bfd_apply(struct peer *peer)
{
	if (peer->bfd_config)
		bgp_peer_config_apply(peer, peer->group);
}

int bgp_nb_peer_bfd_enable_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	if (yang_dnode_get_bool(args->dnode, NULL)) {
		bgp_bfd_enable(peer);
		bgp_nb_peer_bfd_apply(peer);
	} else
		bgp_peer_remove_bfd_config(peer);
	return NB_OK;
}

int bgp_nb_peer_bfd_enable_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (peer)
		bgp_peer_remove_bfd_config(peer);
	return NB_OK;
}

void bgp_nb_cli_show_peer_bfd_enable(struct vty *vty, const struct lyd_node *dnode,
				     bool show_defaults)
{
	const struct lyd_node *bfd = yang_dnode_get_parent(dnode, "bfd-options");
	uint8_t mult = BFD_DEF_DETECT_MULT;
	uint16_t min_rx = BFD_DEF_MIN_RX, min_tx = BFD_DEF_MIN_TX;

	if (!yang_dnode_get_bool(dnode, NULL))
		return;

	if (bfd && yang_dnode_exists(bfd, "./detect-multiplier"))
		mult = yang_dnode_get_uint8(bfd, "./detect-multiplier");
	if (bfd && yang_dnode_exists(bfd, "./required-min-rx"))
		min_rx = yang_dnode_get_uint16(bfd, "./required-min-rx");
	if (bfd && yang_dnode_exists(bfd, "./desired-min-tx"))
		min_tx = yang_dnode_get_uint16(bfd, "./desired-min-tx");

	/*
	 * Print the whole line here. detect-multiplier's cli_show is not
	 * called when the multiplier is 3: lyd_is_default() treats an explicit
	 * 3 as the default, so "neighbor X bfd 3 100 100" would otherwise
	 * disappear from the running configuration.
	 */
	if (mult != BFD_DEF_DETECT_MULT || min_rx != BFD_DEF_MIN_RX || min_tx != BFD_DEF_MIN_TX)
		vty_out(vty, "%sneighbor %s bfd %u %u %u\n", bgp_nb_peer_show_indent(dnode),
			bgp_nb_config_peer_name(dnode), mult, min_rx, min_tx);
	else
		vty_out(vty, "%sneighbor %s bfd\n", bgp_nb_peer_show_indent(dnode),
			bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_bfd_detect_mult_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	bgp_bfd_enable(peer);
	peer->bfd_config->detection_multiplier = yang_dnode_get_uint8(args->dnode, NULL);
	bgp_nb_peer_bfd_apply(peer);
	return NB_OK;
}

int bgp_nb_peer_bfd_min_rx_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	bgp_bfd_enable(peer);
	peer->bfd_config->min_rx = yang_dnode_get_uint16(args->dnode, NULL);
	bgp_nb_peer_bfd_apply(peer);
	return NB_OK;
}

int bgp_nb_peer_bfd_min_tx_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	bgp_bfd_enable(peer);
	peer->bfd_config->min_tx = yang_dnode_get_uint16(args->dnode, NULL);
	bgp_nb_peer_bfd_apply(peer);
	return NB_OK;
}

int bgp_nb_peer_bfd_cbit_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	bgp_bfd_enable(peer);
	peer->bfd_config->cbit = yang_dnode_get_bool(args->dnode, NULL);
	bgp_nb_peer_bfd_apply(peer);
	return NB_OK;
}

void bgp_nb_cli_show_peer_bfd_cbit(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "%sneighbor %s bfd check-control-plane-failure\n",
			bgp_nb_peer_show_indent(dnode), bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_bfd_profile_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	bgp_bfd_enable(peer);
	strlcpy(peer->bfd_config->profile, yang_dnode_get_string(args->dnode, NULL),
		sizeof(peer->bfd_config->profile));
	bgp_nb_peer_bfd_apply(peer);
	return NB_OK;
}

int bgp_nb_peer_bfd_profile_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !peer->bfd_config)
		return NB_OK;

	peer->bfd_config->profile[0] = 0;
	bgp_nb_peer_bfd_apply(peer);
	return NB_OK;
}

void bgp_nb_cli_show_peer_bfd_profile(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults)
{
	vty_out(vty, "%sneighbor %s bfd profile %s\n", bgp_nb_peer_show_indent(dnode),
		bgp_nb_config_peer_name(dnode), yang_dnode_get_string(dnode, NULL));
}

int bgp_nb_peer_bfd_strict_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer, *member;
	struct listnode *node;
	bool strict;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	strict = yang_dnode_get_bool(args->dnode, NULL);
	if (strict)
		peer_flag_set(peer, PEER_FLAG_BFD_STRICT);
	else
		peer_flag_unset(peer, PEER_FLAG_BFD_STRICT);

	/*
	 * A single-hop session whose egress is still unknown stays out of
	 * bfdd. Setting the flag does not retry that install, so BGP waits
	 * for BFD and BFD waits for an interface that appears only once BGP
	 * connects. Strict mode has to install the session now.
	 */
	if (!strict)
		return NB_OK;

	if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		for (ALL_LIST_ELEMENTS_RO(peer->group->peer, node, member))
			bgp_peer_bfd_update_source(member);
	} else
		bgp_peer_bfd_update_source(peer);
	return NB_OK;
}

void bgp_nb_cli_show_peer_bfd_strict(struct vty *vty, const struct lyd_node *dnode,
				     bool show_defaults)
{
	const struct lyd_node *bfd = yang_dnode_get_parent(dnode, "bfd-options");

	if (!yang_dnode_get_bool(dnode, NULL))
		return;

	if (bfd && yang_dnode_exists(bfd, "./strict-hold-time"))
		return;

	vty_out(vty, "%sneighbor %s bfd strict\n", bgp_nb_peer_show_indent(dnode),
		bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_bfd_strict_hold_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	bgp_bfd_enable(peer);
	event_cancel(&peer->bfd_config->t_hold_timer);
	peer->bfd_config->hold_time = yang_dnode_get_uint32(args->dnode, NULL);
	peer_flag_set(peer, PEER_FLAG_BFD_STRICT);
	bgp_nb_peer_bfd_apply(peer);
	return NB_OK;
}

int bgp_nb_peer_bfd_strict_hold_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !peer->bfd_config)
		return NB_OK;

	event_cancel(&peer->bfd_config->t_hold_timer);
	peer->bfd_config->hold_time = BFD_DEF_STRICT_HOLD_TIME;
	bgp_nb_peer_bfd_apply(peer);
	return NB_OK;
}

void bgp_nb_cli_show_peer_bfd_strict_hold(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults)
{
	vty_out(vty, "%sneighbor %s bfd strict hold-time %u\n", bgp_nb_peer_show_indent(dnode),
		bgp_nb_config_peer_name(dnode), yang_dnode_get_uint32(dnode, NULL));
}

int bgp_nb_neighbor_peer_group_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	struct peer_group *group;
	const char *group_name;
	as_t as;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
		peer = bgp_nb_config_peer(args->dnode);
		if (!peer)
			return NB_ERR_VALIDATION;
		if (peer_dynamic_neighbor(peer)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "operation not allowed on a dynamic neighbor");
			return NB_ERR_VALIDATION;
		}
		group_name = yang_dnode_get_string(args->dnode, NULL);
		if (!peer_group_lookup(peer->bgp, group_name)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "Configure the peer-group first");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	group_name = yang_dnode_get_string(args->dnode, NULL);
	group = peer_group_lookup(peer->bgp, group_name);
	if (!group)
		return NB_ERR_NOT_FOUND;

	as = peer->as;
	ret = peer_group_bind(peer->bgp, &peer->connection->su, peer, group, &as);
	if (ret != 0)
		return NB_ERR_RESOURCE;

	if (group->conf->as_type != AS_UNSPECIFIED)
		bgp_nb_need_listening(peer->bgp);
	return NB_OK;
}

static bool bgp_nb_flag_inherited(uint64_t flags, uint64_t override, uint64_t flag)
{
	return CHECK_FLAG(flags, flag) && !CHECK_FLAG(override, flag);
}

static void bgp_nb_drop_session_flag(struct peer *peer, uint64_t flag)
{
	if (!bgp_nb_flag_inherited(peer->flags, peer->flags_override, flag))
		return;
	UNSET_FLAG(peer->flags_invert, flag);
	peer_flag_unset(peer, flag);
}

static void bgp_nb_drop_af_flag(struct peer *peer, afi_t afi, safi_t safi, uint64_t flag)
{
	if (!bgp_nb_flag_inherited(peer->af_flags[afi][safi], peer->af_flags_override[afi][safi],
				   flag))
		return;
	UNSET_FLAG(peer->af_flags_invert[afi][safi], flag);
	peer_af_flag_unset(peer, afi, safi, flag);
}

/* True when the neighbor YANG itself turned GR on or off. */
static bool bgp_nb_neighbor_gr_explicit(const struct lyd_node *nbr)
{
	if (!nbr)
		return false;
	if (yang_dnode_exists(nbr, "graceful-restart/enable") &&
	    yang_dnode_get_bool(nbr, "graceful-restart/enable"))
		return true;
	if (yang_dnode_exists(nbr, "graceful-restart/graceful-restart-helper") &&
	    yang_dnode_get_bool(nbr, "graceful-restart/graceful-restart-helper"))
		return true;
	if (yang_dnode_exists(nbr, "graceful-restart/graceful-restart-disable") &&
	    yang_dnode_get_bool(nbr, "graceful-restart/graceful-restart-disable"))
		return true;
	return false;
}

/*
 * Classic "no neighbor X peer-group" deletes the peer. YANG keeps the
 * neighbor, so after unbind drop every inherited value that is not an
 * explicit override. Unset helpers re-inherit while peer_group_active(),
 * so this runs only after peer_group_unbind().
 */
static void bgp_nb_neighbor_drop_inherited(struct peer *peer, const struct lyd_node *nbr)
{
	static const uint64_t session_flags[] = {
		PEER_FLAG_PASSIVE,
		PEER_FLAG_SHUTDOWN,
		PEER_FLAG_RTT_SHUTDOWN,
		PEER_FLAG_DONT_CAPABILITY,
		PEER_FLAG_OVERRIDE_CAPABILITY,
		PEER_FLAG_STRICT_CAP_MATCH,
		PEER_FLAG_DYNAMIC_CAPABILITY,
		PEER_FLAG_DISABLE_CONNECTED_CHECK,
		PEER_FLAG_CAPABILITY_ENHE,
		PEER_FLAG_ENFORCE_FIRST_AS,
		PEER_FLAG_IFPEER_V6ONLY,
		PEER_FLAG_DISABLE_LINK_BW_ENCODING_IEEE,
		PEER_FLAG_EXTENDED_OPT_PARAMS,
		PEER_FLAG_ROLE_STRICT_MODE,
		PEER_FLAG_LOCAL_AS_NO_PREPEND,
		PEER_FLAG_LOCAL_AS_REPLACE_AS,
		PEER_FLAG_DUAL_AS,
		PEER_FLAG_AIGP,
		PEER_FLAG_GRACEFUL_SHUTDOWN,
		PEER_FLAG_CAPABILITY_SOFT_VERSION_OLD,
		PEER_FLAG_CAPABILITY_SOFT_VERSION_NEW,
		PEER_FLAG_CAPABILITY_FQDN,
		PEER_FLAG_AS_LOOP_DETECTION,
		PEER_FLAG_EXTENDED_LINK_BANDWIDTH,
		PEER_FLAG_LONESOUL,
		PEER_FLAG_CAPABILITY_LINK_LOCAL,
		PEER_FLAG_BFD_STRICT,
		PEER_FLAG_RPKI_STRICT,
		PEER_FLAG_SEND_NHC_ATTRIBUTE,
		PEER_FLAG_IP_TRANSPARENT,
	};
	static const uint64_t af_flags[] = {
		PEER_FLAG_SEND_COMMUNITY,
		PEER_FLAG_SEND_EXT_COMMUNITY,
		PEER_FLAG_SEND_LARGE_COMMUNITY,
		PEER_FLAG_NEXTHOP_SELF,
		PEER_FLAG_REFLECTOR_CLIENT,
		PEER_FLAG_RSERVER_CLIENT,
		PEER_FLAG_SOFT_RECONFIG,
		PEER_FLAG_AS_PATH_UNCHANGED,
		PEER_FLAG_NEXTHOP_UNCHANGED,
		PEER_FLAG_MED_UNCHANGED,
		PEER_FLAG_REMOVE_PRIVATE_AS,
		PEER_FLAG_ORF_PREFIX_SM,
		PEER_FLAG_ORF_PREFIX_RM,
		PEER_FLAG_NEXTHOP_LOCAL_UNCHANGED,
		PEER_FLAG_FORCE_NEXTHOP_SELF,
		PEER_FLAG_REMOVE_PRIVATE_AS_ALL,
		PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE,
		PEER_FLAG_AS_OVERRIDE,
		PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE,
		PEER_FLAG_DISABLE_ADDPATH_RX,
		PEER_FLAG_ACCEPT_OWN,
		PEER_FLAG_SEND_EXT_COMMUNITY_RPKI,
		PEER_FLAG_ADDPATH_RX_PATHS_LIMIT,
		PEER_FLAG_CONFIG_ENCAPSULATION_SRV6,
		PEER_FLAG_CONFIG_ENCAPSULATION_SRV6_RELAX,
		PEER_FLAG_CONFIG_ENCAPSULATION_MPLS,
		PEER_FLAG_UPA,
	};
	afi_t afi;
	safi_t safi;
	unsigned int i;

	if (bgp_nb_flag_inherited(peer->flags, peer->flags_override, PEER_FLAG_PASSWORD)) {
		UNSET_FLAG(peer->flags_invert, PEER_FLAG_PASSWORD);
		peer_password_unset(peer);
	}
	if (bgp_nb_flag_inherited(peer->flags, peer->flags_override, PEER_FLAG_UPDATE_SOURCE)) {
		UNSET_FLAG(peer->flags_invert, PEER_FLAG_UPDATE_SOURCE);
		peer_update_source_unset(peer);
	}
	if (bgp_nb_flag_inherited(peer->flags, peer->flags_override, PEER_FLAG_TIMER)) {
		UNSET_FLAG(peer->flags_invert, PEER_FLAG_TIMER);
		peer_timers_unset(peer);
	}
	if (bgp_nb_flag_inherited(peer->flags, peer->flags_override, PEER_FLAG_TIMER_CONNECT)) {
		UNSET_FLAG(peer->flags_invert, PEER_FLAG_TIMER_CONNECT);
		peer_timers_connect_unset(peer);
	}
	if (bgp_nb_flag_inherited(peer->flags, peer->flags_override, PEER_FLAG_TIMER_DELAYOPEN)) {
		UNSET_FLAG(peer->flags_invert, PEER_FLAG_TIMER_DELAYOPEN);
		peer_timers_delayopen_unset(peer);
	}
	if (bgp_nb_flag_inherited(peer->flags, peer->flags_override, PEER_FLAG_ROUTEADV)) {
		UNSET_FLAG(peer->flags_invert, PEER_FLAG_ROUTEADV);
		peer_advertise_interval_unset(peer);
	}
	if (bgp_nb_flag_inherited(peer->flags, peer->flags_override, PEER_FLAG_LOCAL_AS)) {
		UNSET_FLAG(peer->flags_invert, PEER_FLAG_LOCAL_AS | PEER_FLAG_LOCAL_AS_NO_PREPEND |
						       PEER_FLAG_LOCAL_AS_REPLACE_AS |
						       PEER_FLAG_DUAL_AS);
		peer_local_as_unset(peer);
	}
	if (bgp_nb_flag_inherited(peer->flags, peer->flags_override, PEER_FLAG_TCP_MSS)) {
		UNSET_FLAG(peer->flags_invert, PEER_FLAG_TCP_MSS);
		peer_tcp_mss_unset(peer);
	}
	if (bgp_nb_flag_inherited(peer->flags, peer->flags_override, PEER_FLAG_ROLE)) {
		UNSET_FLAG(peer->flags_invert, PEER_FLAG_ROLE | PEER_FLAG_ROLE_STRICT_MODE);
		peer_role_unset(peer);
		peer->local_role = 0;
	}
	if (bgp_nb_flag_inherited(peer->flags, peer->flags_override, PEER_FLAG_PORT)) {
		UNSET_FLAG(peer->flags_invert, PEER_FLAG_PORT);
		peer_port_unset(peer);
	}
	if (!CHECK_FLAG(peer->flags_override, PEER_FLAG_EBGP_MULTIHOP) &&
	    (peer->cfg_ttl || CHECK_FLAG(peer->flags, PEER_FLAG_EBGP_MULTIHOP)))
		peer_cfg_ttl_set(peer, 0);
	if (peer->gtsm_hops != BGP_GTSM_HOPS_DISABLED &&
	    !(nbr && yang_dnode_exists(nbr, "ttl-security")))
		peer_ttl_security_hops_unset(peer);

	for (i = 0; i < array_size(session_flags); i++)
		bgp_nb_drop_session_flag(peer, session_flags[i]);

	FOREACH_AFI_SAFI (afi, safi) {
		const char *ident = yang_afi_safi_value2identity(afi, safi);
		struct bgp_filter *filter = &peer->filter[afi][safi];
		uint8_t *ov_in = &peer->filter_override[afi][safi][FILTER_IN];
		uint8_t *ov_out = &peer->filter_override[afi][safi][FILTER_OUT];
		const struct lyd_node *enabled = NULL;
		const struct lyd_node *addpath = NULL;
		const char *addpath_type = NULL;
		bool explicit_af = false;
		bool af_on = false;

		for (i = 0; i < array_size(af_flags); i++)
			bgp_nb_drop_af_flag(peer, afi, safi, af_flags[i]);

		if (bgp_nb_flag_inherited(peer->af_flags[afi][safi],
					  peer->af_flags_override[afi][safi],
					  PEER_FLAG_MAX_PREFIX)) {
			UNSET_FLAG(peer->af_flags_invert[afi][safi], PEER_FLAG_MAX_PREFIX);
			peer_maximum_prefix_unset(peer, afi, safi);
		}
		if (bgp_nb_flag_inherited(peer->af_flags[afi][safi],
					  peer->af_flags_override[afi][safi],
					  PEER_FLAG_MAX_PREFIX_OUT)) {
			UNSET_FLAG(peer->af_flags_invert[afi][safi], PEER_FLAG_MAX_PREFIX_OUT);
			peer_maximum_prefix_out_unset(peer, afi, safi);
		}
		if (bgp_nb_flag_inherited(peer->af_flags[afi][safi],
					  peer->af_flags_override[afi][safi],
					  PEER_FLAG_ALLOWAS_IN)) {
			UNSET_FLAG(peer->af_flags_invert[afi][safi],
				   PEER_FLAG_ALLOWAS_IN | PEER_FLAG_ALLOWAS_IN_ORIGIN);
			peer_allowas_in_unset(peer, afi, safi);
		}
		if (bgp_nb_flag_inherited(peer->af_flags[afi][safi],
					  peer->af_flags_override[afi][safi], PEER_FLAG_WEIGHT)) {
			UNSET_FLAG(peer->af_flags_invert[afi][safi], PEER_FLAG_WEIGHT);
			peer_weight_unset(peer, afi, safi);
		}
		if (bgp_nb_flag_inherited(peer->af_flags[afi][safi],
					  peer->af_flags_override[afi][safi],
					  PEER_FLAG_DEFAULT_ORIGINATE)) {
			UNSET_FLAG(peer->af_flags_invert[afi][safi], PEER_FLAG_DEFAULT_ORIGINATE);
			peer_default_originate_unset(peer, afi, safi);
		}
		if (!CHECK_FLAG(peer->af_flags_override[afi][safi], PEER_FLAG_SOO) &&
		    peer->soo[afi][safi]) {
			ecommunity_free(&peer->soo[afi][safi]);
			bgp_nb_drop_af_flag(peer, afi, safi, PEER_FLAG_SOO);
		}

		if (!CHECK_FLAG(*ov_in, PEER_FT_DISTRIBUTE_LIST) && filter->dlist[FILTER_IN].name)
			peer_distribute_unset(peer, afi, safi, FILTER_IN);
		if (!CHECK_FLAG(*ov_out, PEER_FT_DISTRIBUTE_LIST) && filter->dlist[FILTER_OUT].name)
			peer_distribute_unset(peer, afi, safi, FILTER_OUT);
		if (!CHECK_FLAG(*ov_in, PEER_FT_PREFIX_LIST) && filter->plist[FILTER_IN].name)
			peer_prefix_list_unset(peer, afi, safi, FILTER_IN);
		if (!CHECK_FLAG(*ov_out, PEER_FT_PREFIX_LIST) && filter->plist[FILTER_OUT].name)
			peer_prefix_list_unset(peer, afi, safi, FILTER_OUT);
		if (!CHECK_FLAG(*ov_in, PEER_FT_FILTER_LIST) && filter->aslist[FILTER_IN].name)
			peer_aslist_unset(peer, afi, safi, FILTER_IN);
		if (!CHECK_FLAG(*ov_out, PEER_FT_FILTER_LIST) && filter->aslist[FILTER_OUT].name)
			peer_aslist_unset(peer, afi, safi, FILTER_OUT);
		if (!CHECK_FLAG(*ov_in, PEER_FT_ROUTE_MAP) && filter->map[RMAP_IN].name)
			peer_route_map_unset(peer, afi, safi, RMAP_IN);
		if (!CHECK_FLAG(*ov_out, PEER_FT_ROUTE_MAP) && filter->map[RMAP_OUT].name)
			peer_route_map_unset(peer, afi, safi, RMAP_OUT);
		if (!CHECK_FLAG(peer->filter_override[afi][safi][0], PEER_FT_UNSUPPRESS_MAP) &&
		    filter->usmap.name)
			peer_unsuppress_map_unset(peer, afi, safi);
		if (!CHECK_FLAG(*ov_out, PEER_FT_ADVERTISE_MAP) && filter->advmap.aname)
			peer_advertise_map_unset(peer, afi, safi, filter->advmap.aname,
						 filter->advmap.amap, filter->advmap.cname,
						 filter->advmap.cmap, filter->advmap.condition);

		if (ident && nbr) {
			enabled = yang_dnode_getf(nbr,
						  "afi-safis/afi-safi[afi-safi-name='%s']/enabled",
						  ident);
			addpath =
				yang_dnode_getf(nbr,
						"afi-safis/afi-safi[afi-safi-name='%s']/add-paths/path-type",
						ident);
		}
		if (enabled) {
			explicit_af = true;
			af_on = yang_dnode_get_bool(enabled, NULL);
		}
		if (explicit_af) {
			if (af_on && !peer->afc[afi][safi])
				peer_activate(peer, afi, safi);
			else if (!af_on && peer->afc[afi][safi])
				peer_deactivate(peer, afi, safi);
		} else if (peer->bgp->default_af[afi][safi]) {
			if (!peer->afc[afi][safi])
				peer_activate(peer, afi, safi);
		} else if (peer->afc[afi][safi]) {
			peer_deactivate(peer, afi, safi);
		}

		if (addpath)
			addpath_type = yang_dnode_get_string(addpath, NULL);
		if (peer->addpath_type[afi][safi] != BGP_ADDPATH_NONE &&
		    (!addpath_type || strmatch(addpath_type, "none")))
			bgp_addpath_set_peer_type(peer, afi, safi, BGP_ADDPATH_NONE, 0);
	}

	/* Remote-as after AF flags so iBGP-only unsets still see the group AS. */
	if (!CHECK_FLAG(peer->flags_override, PEER_FLAG_REMOTE_AS)) {
		if (nbr && yang_dnode_exists(nbr, "neighbor-remote-as/remote-as-type"))
			SET_FLAG(peer->flags_override, PEER_FLAG_REMOTE_AS);
		else
			peer_as_change(peer, 0, AS_UNSPECIFIED, NULL);
	}

	if (!bgp_nb_neighbor_gr_explicit(nbr))
		bgp_peer_move_to_gr_mode(peer, PEER_GLOBAL_INHERIT);

	if (peer->bfd_config && !(nbr && yang_dnode_exists(nbr, "bfd-options/enable") &&
				  yang_dnode_get_bool(nbr, "bfd-options/enable")))
		bgp_peer_remove_bfd_config(peer);
}

int bgp_nb_neighbor_peer_group_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;
	const struct lyd_node *nbr;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !peer->group)
		return NB_OK;

	if (peer_group_unbind(peer->bgp, peer, peer->group) != 0)
		return NB_ERR_RESOURCE;

	nbr = yang_dnode_get_parent(args->dnode, "neighbor");
	if (!nbr)
		nbr = yang_dnode_get_parent(args->dnode, "unnumbered-neighbor");
	bgp_nb_neighbor_drop_inherited(peer, nbr);

	FOREACH_AFI_SAFI (afi, safi) {
		struct peer_af *paf = peer_af_find(peer, afi, safi);

		if (paf)
			update_group_adjust_peer(paf);
	}
	return NB_OK;
}

void bgp_nb_cli_show_neighbor_peer_group(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults)
{
	vty_out(vty, "%sneighbor %s peer-group %s\n", bgp_nb_peer_show_indent(dnode),
		bgp_nb_config_peer_name(dnode), yang_dnode_get_string(dnode, NULL));
}

int bgp_nb_neighbor_local_port_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	peer_port_set(peer, yang_dnode_get_uint16(args->dnode, NULL));
	return NB_OK;
}

int bgp_nb_neighbor_local_port_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (peer)
		peer_port_unset(peer);
	return NB_OK;
}

void bgp_nb_cli_show_neighbor_local_port(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults)
{
	uint16_t port = yang_dnode_get_uint16(dnode, NULL);

	if (port == BGP_PORT_DEFAULT && !show_defaults)
		return;

	vty_out(vty, " neighbor %s port %u\n", bgp_nb_config_peer_name(dnode), port);
}


/*
 * Neighbor AFI/SAFI helpers and callbacks
 */
static bool bgp_nb_dnode_afi_safi(const struct lyd_node *dnode, afi_t *afi, safi_t *safi)
{
	const struct lyd_node *af;
	const char *name;

	af = yang_dnode_get_parent(dnode, "afi-safi");
	if (!af)
		return false;

	name = yang_dnode_get_string(af, "./afi-safi-name");
	yang_afi_safi_identity2value(name, afi, safi);
	return true;
}

static int bgp_nb_peer_af_flag_modify(struct nb_cb_modify_args *args, uint64_t flag)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	if (yang_dnode_get_bool(args->dnode, NULL)) {
		if (peer_af_flag_set(peer, afi, safi, flag) < 0)
			return NB_ERR_RESOURCE;
	} else {
		if (peer_af_flag_unset(peer, afi, safi, flag) < 0)
			return NB_ERR_RESOURCE;
	}
	return NB_OK;
}

int bgp_nb_peer_afi_safi_create(struct nb_cb_create_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	const char *name;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	name = yang_dnode_get_string(args->dnode, "./afi-safi-name");
	yang_afi_safi_identity2value(name, &afi, &safi);

	if (yang_dnode_exists(args->dnode, "./enabled") &&
	    yang_dnode_get_bool(args->dnode, "./enabled"))
		peer_activate(peer, afi, safi);

	return NB_OK;
}

int bgp_nb_peer_afi_safi_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	const char *name;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_OK;

	name = yang_dnode_get_string(args->dnode, "./afi-safi-name");
	yang_afi_safi_identity2value(name, &afi, &safi);
	peer_deactivate(peer, afi, safi);
	return NB_OK;
}

int bgp_nb_peer_af_enabled_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	if (yang_dnode_get_bool(args->dnode, NULL)) {
		if (peer_activate(peer, afi, safi) < 0)
			return NB_ERR_RESOURCE;
	} else {
		if (peer_deactivate(peer, afi, safi) < 0)
			return NB_ERR_RESOURCE;
	}
	return NB_OK;
}

int bgp_nb_peer_af_enabled_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	peer_deactivate(peer, afi, safi);
	return NB_OK;
}

void bgp_nb_cli_show_peer_af_enabled(struct vty *vty, const struct lyd_node *dnode,
				     bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "%sneighbor %s activate\n", bgp_nb_peer_show_indent(dnode),
			bgp_nb_config_peer_name(dnode));
	else if (show_defaults)
		vty_out(vty, "%sno neighbor %s activate\n", bgp_nb_peer_show_indent(dnode),
			bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_af_soft_reconfig_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_flag_modify(args, PEER_FLAG_SOFT_RECONFIG);
}

void bgp_nb_cli_show_peer_af_soft_reconfig(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "%sneighbor %s soft-reconfiguration inbound\n",
			bgp_nb_peer_show_indent(dnode), bgp_nb_config_peer_name(dnode));
	else if (show_defaults)
		vty_out(vty, "%sno neighbor %s soft-reconfiguration inbound\n",
			bgp_nb_peer_show_indent(dnode), bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_af_nexthop_self_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_flag_modify(args, PEER_FLAG_NEXTHOP_SELF);
}

void bgp_nb_cli_show_peer_af_nexthop_self(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "%sneighbor %s next-hop-self\n", bgp_nb_peer_show_indent(dnode),
			bgp_nb_config_peer_name(dnode));
	else if (show_defaults)
		vty_out(vty, "%sno neighbor %s next-hop-self\n", bgp_nb_peer_show_indent(dnode),
			bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_af_nexthop_self_force_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_flag_modify(args, PEER_FLAG_FORCE_NEXTHOP_SELF);
}

void bgp_nb_cli_show_peer_af_nexthop_self_force(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "%sneighbor %s next-hop-self force\n", bgp_nb_peer_show_indent(dnode),
			bgp_nb_config_peer_name(dnode));
	else if (show_defaults)
		vty_out(vty, "%sno neighbor %s next-hop-self force\n",
			bgp_nb_peer_show_indent(dnode), bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_af_aspath_unchanged_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_flag_modify(args, PEER_FLAG_AS_PATH_UNCHANGED);
}

static void bgp_nb_cli_show_attr_unchanged(struct vty *vty, const struct lyd_node *dnode,
					   const char *self)
{
	const struct lyd_node *parent;
	bool aspath, nexthop, med;

	if (!yang_dnode_get_bool(dnode, NULL))
		return;

	parent = yang_dnode_get_parent(dnode, "attr-unchanged");
	if (!parent)
		return;

	aspath = yang_dnode_exists(parent, "as-path-unchanged") &&
		 yang_dnode_get_bool(parent, "as-path-unchanged");
	nexthop = yang_dnode_exists(parent, "next-hop-unchanged") &&
		  yang_dnode_get_bool(parent, "next-hop-unchanged");
	med = yang_dnode_exists(parent, "med-unchanged") &&
	      yang_dnode_get_bool(parent, "med-unchanged");

	/*
	 * The three leaves are one CLI command. Emit it once, from the last
	 * enabled keyword, so frr-reload does not keep only the last line.
	 */
	if (strmatch(self, "as-path") && (nexthop || med))
		return;
	if (strmatch(self, "next-hop") && med)
		return;

	vty_out(vty, "%sneighbor %s attribute-unchanged%s%s%s\n", bgp_nb_peer_show_indent(dnode),
		bgp_nb_config_peer_name(dnode), aspath ? " as-path" : "",
		nexthop ? " next-hop" : "", med ? " med" : "");
}

void bgp_nb_cli_show_peer_af_aspath_unchanged(struct vty *vty, const struct lyd_node *dnode,
					      bool show_defaults)
{
	bgp_nb_cli_show_attr_unchanged(vty, dnode, "as-path");
}

int bgp_nb_peer_af_nexthop_unchanged_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_flag_modify(args, PEER_FLAG_NEXTHOP_UNCHANGED);
}

void bgp_nb_cli_show_peer_af_nexthop_unchanged(struct vty *vty, const struct lyd_node *dnode,
					       bool show_defaults)
{
	bgp_nb_cli_show_attr_unchanged(vty, dnode, "next-hop");
}

int bgp_nb_peer_af_med_unchanged_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_flag_modify(args, PEER_FLAG_MED_UNCHANGED);
}

void bgp_nb_cli_show_peer_af_med_unchanged(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	bgp_nb_cli_show_attr_unchanged(vty, dnode, "med");
}

int bgp_nb_peer_af_as_override_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_flag_modify(args, PEER_FLAG_AS_OVERRIDE);
}

void bgp_nb_cli_show_peer_af_as_override(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "%sneighbor %s as-override\n", bgp_nb_peer_show_indent(dnode),
			bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_af_remove_private_as_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_flag_modify(args, PEER_FLAG_REMOVE_PRIVATE_AS);
}

static bool bgp_nb_sib_bool(const struct lyd_node *dnode, const char *rel)
{
	return yang_dnode_exists(dnode, rel) && yang_dnode_get_bool(dnode, "%s", rel);
}

void bgp_nb_cli_show_peer_af_remove_private_as(struct vty *vty, const struct lyd_node *dnode,
					       bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		return;
	if (bgp_nb_sib_bool(dnode, "../remove-private-as-all-replace") ||
	    bgp_nb_sib_bool(dnode, "../remove-private-as-replace") ||
	    bgp_nb_sib_bool(dnode, "../remove-private-as-all"))
		return;
	vty_out(vty, "%sneighbor %s remove-private-AS\n", bgp_nb_peer_show_indent(dnode),
		bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_af_remove_private_as_all_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_flag_modify(args, PEER_FLAG_REMOVE_PRIVATE_AS_ALL);
}

void bgp_nb_cli_show_peer_af_remove_private_as_all(struct vty *vty, const struct lyd_node *dnode,
						   bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		return;
	if (bgp_nb_sib_bool(dnode, "../remove-private-as-all-replace") ||
	    bgp_nb_sib_bool(dnode, "../remove-private-as-replace"))
		return;
	vty_out(vty, "%sneighbor %s remove-private-AS all\n", bgp_nb_peer_show_indent(dnode),
		bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_af_remove_private_as_replace_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_flag_modify(args, PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE);
}

void bgp_nb_cli_show_peer_af_remove_private_as_replace(struct vty *vty,
						       const struct lyd_node *dnode,
						       bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		return;
	if (bgp_nb_sib_bool(dnode, "../remove-private-as-all-replace"))
		return;
	vty_out(vty, "%sneighbor %s remove-private-AS replace-AS\n", bgp_nb_peer_show_indent(dnode),
		bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_af_remove_private_as_all_replace_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_flag_modify(args, PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE);
}

void bgp_nb_cli_show_peer_af_remove_private_as_all_replace(struct vty *vty,
							   const struct lyd_node *dnode,
							   bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "%sneighbor %s remove-private-AS all replace-AS\n",
			bgp_nb_peer_show_indent(dnode), bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_af_reflector_client_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_flag_modify(args, PEER_FLAG_REFLECTOR_CLIENT);
}

void bgp_nb_cli_show_peer_af_reflector_client(struct vty *vty, const struct lyd_node *dnode,
					      bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "%sneighbor %s route-reflector-client\n",
			bgp_nb_peer_show_indent(dnode), bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_af_rserver_client_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_flag_modify(args, PEER_FLAG_RSERVER_CLIENT);
}

void bgp_nb_cli_show_peer_af_rserver_client(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "%sneighbor %s route-server-client\n", bgp_nb_peer_show_indent(dnode),
			bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_af_weight_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	uint16_t weight;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	weight = yang_dnode_get_uint16(args->dnode, NULL);
	if (peer_weight_set(peer, afi, safi, weight) < 0)
		return NB_ERR_RESOURCE;
	return NB_OK;
}

int bgp_nb_peer_af_weight_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	peer_weight_unset(peer, afi, safi);
	return NB_OK;
}

void bgp_nb_cli_show_peer_af_weight(struct vty *vty, const struct lyd_node *dnode,
				    bool show_defaults)
{
	vty_out(vty, "%sneighbor %s weight %" PRIu16 "\n", bgp_nb_peer_show_indent(dnode),
		bgp_nb_config_peer_name(dnode), yang_dnode_get_uint16(dnode, NULL));
}

int bgp_nb_peer_af_send_community_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_flag_modify(args, PEER_FLAG_SEND_COMMUNITY);
}

void bgp_nb_cli_show_peer_af_send_community(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "%sno neighbor %s send-community\n", bgp_nb_peer_show_indent(dnode),
			bgp_nb_config_peer_name(dnode));
	else if (show_defaults)
		vty_out(vty, "%sneighbor %s send-community\n", bgp_nb_peer_show_indent(dnode),
			bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_af_send_ext_community_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_flag_modify(args, PEER_FLAG_SEND_EXT_COMMUNITY);
}

void bgp_nb_cli_show_peer_af_send_ext_community(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "%sno neighbor %s send-community extended\n",
			bgp_nb_peer_show_indent(dnode), bgp_nb_config_peer_name(dnode));
	else if (show_defaults)
		vty_out(vty, "%sneighbor %s send-community extended\n",
			bgp_nb_peer_show_indent(dnode), bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_af_send_large_community_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_flag_modify(args, PEER_FLAG_SEND_LARGE_COMMUNITY);
}

void bgp_nb_cli_show_peer_af_send_large_community(struct vty *vty, const struct lyd_node *dnode,
						  bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "%sno neighbor %s send-community large\n",
			bgp_nb_peer_show_indent(dnode), bgp_nb_config_peer_name(dnode));
	else if (show_defaults)
		vty_out(vty, "%sneighbor %s send-community large\n",
			bgp_nb_peer_show_indent(dnode), bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_af_send_ext_community_rpki_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_flag_modify(args, PEER_FLAG_SEND_EXT_COMMUNITY_RPKI);
}

void bgp_nb_cli_show_peer_af_send_ext_community_rpki(struct vty *vty, const struct lyd_node *dnode,
						     bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "%sneighbor %s send-community extended rpki\n",
			bgp_nb_peer_show_indent(dnode), bgp_nb_config_peer_name(dnode));
}

static const char *bgp_nb_af_allowas_rmap(const struct lyd_node *dnode)
{
	const struct lyd_node *opts;

	opts = yang_dnode_get_parent(dnode, "as-path-options");
	if (!opts)
		return NULL;
	if (!yang_dnode_exists(opts, "./allowas-in-route-map"))
		return NULL;
	return yang_dnode_get_string(opts, "./allowas-in-route-map");
}

int bgp_nb_peer_af_allow_own_as_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	uint8_t allow_num;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	allow_num = yang_dnode_get_uint8(args->dnode, NULL);
	if (peer_allowas_in_set(peer, afi, safi, allow_num, false,
				bgp_nb_af_allowas_rmap(args->dnode)) < 0)
		return NB_ERR_RESOURCE;
	return NB_OK;
}

int bgp_nb_peer_af_allow_own_as_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	peer_allowas_in_unset(peer, afi, safi);
	return NB_OK;
}

void bgp_nb_cli_show_peer_af_allow_own_as(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults)
{
	const char *rmap = bgp_nb_af_allowas_rmap(dnode);
	uint8_t num = yang_dnode_get_uint8(dnode, NULL);

	if (rmap) {
		if (num == BGP_ALLOWAS_IN_DEFAULT)
			vty_out(vty, "%sneighbor %s allowas-in route-map %s\n",
				bgp_nb_peer_show_indent(dnode), bgp_nb_config_peer_name(dnode),
				rmap);
		else
			vty_out(vty, "%sneighbor %s allowas-in route-map %s %u\n",
				bgp_nb_peer_show_indent(dnode), bgp_nb_config_peer_name(dnode),
				rmap, num);
	} else if (num == BGP_ALLOWAS_IN_DEFAULT) {
		vty_out(vty, "%sneighbor %s allowas-in\n", bgp_nb_peer_show_indent(dnode),
			bgp_nb_config_peer_name(dnode));
	} else {
		vty_out(vty, "%sneighbor %s allowas-in %u\n", bgp_nb_peer_show_indent(dnode),
			bgp_nb_config_peer_name(dnode), num);
	}
}

int bgp_nb_peer_af_allow_own_origin_as_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	if (!yang_dnode_get_bool(args->dnode, NULL)) {
		peer_allowas_in_unset(peer, afi, safi);
		return NB_OK;
	}

	if (peer_allowas_in_set(peer, afi, safi, 0, true, bgp_nb_af_allowas_rmap(args->dnode)) < 0)
		return NB_ERR_RESOURCE;
	return NB_OK;
}

int bgp_nb_peer_af_allow_own_origin_as_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	peer_allowas_in_unset(peer, afi, safi);
	return NB_OK;
}

void bgp_nb_cli_show_peer_af_allow_own_origin_as(struct vty *vty, const struct lyd_node *dnode,
						 bool show_defaults)
{
	const char *rmap;

	if (!yang_dnode_get_bool(dnode, NULL))
		return;

	rmap = bgp_nb_af_allowas_rmap(dnode);
	if (rmap)
		vty_out(vty, "%sneighbor %s allowas-in route-map %s origin\n",
			bgp_nb_peer_show_indent(dnode), bgp_nb_config_peer_name(dnode), rmap);
	else
		vty_out(vty, "%sneighbor %s allowas-in origin\n", bgp_nb_peer_show_indent(dnode),
			bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_af_allowas_in_rmap_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	const struct lyd_node *opts;
	const char *rmap;
	bool origin;
	int allow_num;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	opts = yang_dnode_get_parent(args->dnode, "as-path-options");
	if (!opts)
		return NB_ERR_NOT_FOUND;

	rmap = yang_dnode_get_string(args->dnode, NULL);
	origin = yang_dnode_exists(opts, "./allow-own-origin-as") &&
		 yang_dnode_get_bool(opts, "./allow-own-origin-as");
	if (origin)
		allow_num = 0;
	else if (yang_dnode_exists(opts, "./allow-own-as"))
		allow_num = yang_dnode_get_uint8(opts, "./allow-own-as");
	else
		allow_num = BGP_ALLOWAS_IN_DEFAULT;

	if (peer_allowas_in_set(peer, afi, safi, allow_num, origin, rmap) < 0)
		return NB_ERR_RESOURCE;
	return NB_OK;
}

int bgp_nb_peer_af_allowas_in_rmap_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	const struct lyd_node *opts;
	bool origin;
	int allow_num;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	opts = yang_dnode_get_parent(args->dnode, "as-path-options");
	if (!opts)
		return NB_OK;

	/* If allowas-in itself is gone, unset already handled elsewhere. */
	if (!yang_dnode_exists(opts, "./allow-own-as") &&
	    !(yang_dnode_exists(opts, "./allow-own-origin-as") &&
	      yang_dnode_get_bool(opts, "./allow-own-origin-as")))
		return NB_OK;

	origin = yang_dnode_exists(opts, "./allow-own-origin-as") &&
		 yang_dnode_get_bool(opts, "./allow-own-origin-as");
	if (origin)
		allow_num = 0;
	else
		allow_num = yang_dnode_get_uint8(opts, "./allow-own-as");

	if (peer_allowas_in_set(peer, afi, safi, allow_num, origin, NULL) < 0)
		return NB_ERR_RESOURCE;
	return NB_OK;
}

void bgp_nb_cli_show_peer_af_allowas_in_rmap(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults)
{
	/* Printed with allow-own-as / allow-own-origin-as cli_show. */
}

static const char *bgp_nb_af_default_originate_rmap(const struct lyd_node *dnode)
{
	const struct lyd_node *cont;

	cont = yang_dnode_get_parent(dnode, "default-originate");
	if (!cont)
		return NULL;
	if (!yang_dnode_exists(cont, "./route-map"))
		return NULL;
	return yang_dnode_get_string(cont, "./route-map");
}

int bgp_nb_peer_af_default_originate_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	const char *rmap;
	struct route_map *map = NULL;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	if (!yang_dnode_get_bool(args->dnode, NULL)) {
		peer_default_originate_unset(peer, afi, safi);
		return NB_OK;
	}

	rmap = bgp_nb_af_default_originate_rmap(args->dnode);
	if (rmap)
		map = route_map_lookup_by_name(rmap);
	if (peer_default_originate_set(peer, afi, safi, rmap, map) < 0)
		return NB_ERR_RESOURCE;
	return NB_OK;
}

int bgp_nb_peer_af_default_originate_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	peer_default_originate_unset(peer, afi, safi);
	return NB_OK;
}

void bgp_nb_cli_show_peer_af_default_originate(struct vty *vty, const struct lyd_node *dnode,
					       bool show_defaults)
{
	const char *rmap;

	if (!yang_dnode_get_bool(dnode, NULL))
		return;

	rmap = bgp_nb_af_default_originate_rmap(dnode);
	if (rmap)
		vty_out(vty, "%sneighbor %s default-originate route-map %s\n",
			bgp_nb_peer_show_indent(dnode), bgp_nb_config_peer_name(dnode), rmap);
	else
		vty_out(vty, "%sneighbor %s default-originate\n", bgp_nb_peer_show_indent(dnode),
			bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_af_default_originate_rmap_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	const char *rmap;
	struct route_map *map;
	const struct lyd_node *cont;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	cont = yang_dnode_get_parent(args->dnode, "default-originate");
	if (!cont || !yang_dnode_exists(cont, "./originate") ||
	    !yang_dnode_get_bool(cont, "./originate"))
		return NB_OK;

	rmap = yang_dnode_get_string(args->dnode, NULL);
	map = route_map_lookup_by_name(rmap);
	if (peer_default_originate_set(peer, afi, safi, rmap, map) < 0)
		return NB_ERR_RESOURCE;
	return NB_OK;
}

/*
 * Destroy callbacks run before modifies. "no neighbor X default-originate"
 * deletes the route-map and sets originate false, but the deleted node's
 * parent still shows originate true. Read the commit candidate.
 * Advertising with a NULL map here would leak an unfiltered default
 * before the unset. The candidate is the transaction being applied, so
 * this covers CLI, sysrepo, and any other northbound client.
 */
static bool bgp_nb_default_originate_remains(struct nb_cb_destroy_args *args)
{
	const struct lyd_node *root;
	char path[XPATH_MAXLEN];
	char *slash, *leaf;

	root = nb_transaction_candidate_dnode();
	if (!root) {
		zlog_warn("%s: no commit candidate; keeping default-originate", __func__);
		return true;
	}

	if (!yang_dnode_get_path(args->dnode, path, sizeof(path)))
		return true;

	slash = strrchr(path, '/');
	leaf = slash ? slash + 1 : path;
	if (strchr(leaf, ':'))
		leaf = strchr(leaf, ':') + 1;
	if (!strmatch(leaf, "route-map"))
		return true;

	strlcpy(leaf, "originate", path + sizeof(path) - leaf);
	if (!yang_dnode_exists(root, path))
		return false;
	return yang_dnode_get_bool(root, "%s", path);
}

int bgp_nb_peer_af_default_originate_rmap_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	if (!CHECK_FLAG(peer->af_flags[afi][safi], PEER_FLAG_DEFAULT_ORIGINATE))
		return NB_OK;

	if (!bgp_nb_default_originate_remains(args))
		return NB_OK;

	if (peer_default_originate_set(peer, afi, safi, NULL, NULL) < 0)
		zlog_warn("%s: failed to clear default-originate route-map on %s", __func__,
			  peer->host);
	return NB_OK;
}

void bgp_nb_cli_show_peer_af_default_originate_rmap(struct vty *vty, const struct lyd_node *dnode,
						    bool show_defaults)
{
	/* Printed with originate cli_show. */
}

static int bgp_nb_peer_af_named_filter_modify(struct nb_cb_modify_args *args, int direct,
					      int (*set_fn)(struct peer *, afi_t, safi_t, int,
							    const char *),
					      const char *conflict)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	const char *name;

	switch (args->event) {
	case NB_EV_VALIDATE:
		/*
		 * The other list may be created in this same candidate, so
		 * read the candidate rather than the live peer filter.
		 */
		if (conflict && yang_dnode_exists(args->dnode, conflict)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "Prefix/distribute list can not co-exist");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	name = yang_dnode_get_string(args->dnode, NULL);
	if (set_fn(peer, afi, safi, direct, name) < 0)
		return NB_ERR_RESOURCE;
	return NB_OK;
}

static int bgp_nb_peer_af_named_filter_destroy(struct nb_cb_destroy_args *args, int direct,
					       int (*unset_fn)(struct peer *, afi_t, safi_t, int))
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	unset_fn(peer, afi, safi, direct);
	return NB_OK;
}

int bgp_nb_peer_af_plist_import_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_named_filter_modify(args, FILTER_IN, peer_prefix_list_set,
						  "../access-list-import");
}

int bgp_nb_peer_af_plist_import_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_peer_af_named_filter_destroy(args, FILTER_IN, peer_prefix_list_unset);
}

void bgp_nb_cli_show_peer_af_plist_import(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults)
{
	vty_out(vty, "%sneighbor %s prefix-list %s in\n", bgp_nb_peer_show_indent(dnode),
		bgp_nb_config_peer_name(dnode), yang_dnode_get_string(dnode, NULL));
}

int bgp_nb_peer_af_plist_export_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_named_filter_modify(args, FILTER_OUT, peer_prefix_list_set,
						  "../access-list-export");
}

int bgp_nb_peer_af_plist_export_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_peer_af_named_filter_destroy(args, FILTER_OUT, peer_prefix_list_unset);
}

void bgp_nb_cli_show_peer_af_plist_export(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults)
{
	vty_out(vty, "%sneighbor %s prefix-list %s out\n", bgp_nb_peer_show_indent(dnode),
		bgp_nb_config_peer_name(dnode), yang_dnode_get_string(dnode, NULL));
}

int bgp_nb_peer_af_access_list_import_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_named_filter_modify(args, FILTER_IN, peer_distribute_set,
						  "../plist-import");
}

int bgp_nb_peer_af_access_list_import_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_peer_af_named_filter_destroy(args, FILTER_IN, peer_distribute_unset);
}

void bgp_nb_cli_show_peer_af_access_list_import(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults)
{
	vty_out(vty, "%sneighbor %s distribute-list %s in\n", bgp_nb_peer_show_indent(dnode),
		bgp_nb_config_peer_name(dnode), yang_dnode_get_string(dnode, NULL));
}

int bgp_nb_peer_af_access_list_export_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_named_filter_modify(args, FILTER_OUT, peer_distribute_set,
						  "../plist-export");
}

int bgp_nb_peer_af_access_list_export_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_peer_af_named_filter_destroy(args, FILTER_OUT, peer_distribute_unset);
}

void bgp_nb_cli_show_peer_af_access_list_export(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults)
{
	vty_out(vty, "%sneighbor %s distribute-list %s out\n", bgp_nb_peer_show_indent(dnode),
		bgp_nb_config_peer_name(dnode), yang_dnode_get_string(dnode, NULL));
}

int bgp_nb_peer_af_aspath_filter_import_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_named_filter_modify(args, FILTER_IN, peer_aslist_set, NULL);
}

int bgp_nb_peer_af_aspath_filter_import_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_peer_af_named_filter_destroy(args, FILTER_IN, peer_aslist_unset);
}

void bgp_nb_cli_show_peer_af_aspath_filter_import(struct vty *vty, const struct lyd_node *dnode,
						  bool show_defaults)
{
	vty_out(vty, "%sneighbor %s filter-list %s in\n", bgp_nb_peer_show_indent(dnode),
		bgp_nb_config_peer_name(dnode), yang_dnode_get_string(dnode, NULL));
}

int bgp_nb_peer_af_aspath_filter_export_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_named_filter_modify(args, FILTER_OUT, peer_aslist_set, NULL);
}

int bgp_nb_peer_af_aspath_filter_export_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_peer_af_named_filter_destroy(args, FILTER_OUT, peer_aslist_unset);
}

void bgp_nb_cli_show_peer_af_aspath_filter_export(struct vty *vty, const struct lyd_node *dnode,
						  bool show_defaults)
{
	vty_out(vty, "%sneighbor %s filter-list %s out\n", bgp_nb_peer_show_indent(dnode),
		bgp_nb_config_peer_name(dnode), yang_dnode_get_string(dnode, NULL));
}

int bgp_nb_peer_af_rmap_import_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	const char *name;
	struct route_map *map;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	name = yang_dnode_get_string(args->dnode, NULL);
	map = route_map_lookup_by_name(name);
	if (peer_route_map_set(peer, afi, safi, RMAP_IN, name, map) < 0)
		return NB_ERR_RESOURCE;
	return NB_OK;
}

int bgp_nb_peer_af_rmap_import_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	peer_route_map_unset(peer, afi, safi, RMAP_IN);
	return NB_OK;
}

void bgp_nb_cli_show_peer_af_rmap_import(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults)
{
	vty_out(vty, "%sneighbor %s route-map %s in\n", bgp_nb_peer_show_indent(dnode),
		bgp_nb_config_peer_name(dnode), yang_dnode_get_string(dnode, NULL));
}

int bgp_nb_peer_af_rmap_export_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	const char *name;
	struct route_map *map;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	name = yang_dnode_get_string(args->dnode, NULL);
	map = route_map_lookup_by_name(name);
	if (peer_route_map_set(peer, afi, safi, RMAP_OUT, name, map) < 0)
		return NB_ERR_RESOURCE;
	return NB_OK;
}

int bgp_nb_peer_af_rmap_export_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	peer_route_map_unset(peer, afi, safi, RMAP_OUT);
	return NB_OK;
}

void bgp_nb_cli_show_peer_af_rmap_export(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults)
{
	vty_out(vty, "%sneighbor %s route-map %s out\n", bgp_nb_peer_show_indent(dnode),
		bgp_nb_config_peer_name(dnode), yang_dnode_get_string(dnode, NULL));
}

int bgp_nb_peer_af_unsuppress_map_export_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	const char *name;
	struct route_map *map;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	name = yang_dnode_get_string(args->dnode, NULL);
	map = route_map_lookup_by_name(name);
	if (peer_unsuppress_map_set(peer, afi, safi, name, map) < 0)
		return NB_ERR_RESOURCE;
	return NB_OK;
}

int bgp_nb_peer_af_unsuppress_map_export_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	peer_unsuppress_map_unset(peer, afi, safi);
	return NB_OK;
}

void bgp_nb_cli_show_peer_af_unsuppress_map_export(struct vty *vty, const struct lyd_node *dnode,
						   bool show_defaults)
{
	vty_out(vty, "%sneighbor %s unsuppress-map %s\n", bgp_nb_peer_show_indent(dnode),
		bgp_nb_config_peer_name(dnode), yang_dnode_get_string(dnode, NULL));
}

static int bgp_nb_peer_af_max_prefix_in_apply(const struct lyd_node *dir)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	uint32_t max;
	uint8_t threshold = MAXIMUM_PREFIX_THRESHOLD_DEFAULT;
	uint16_t restart = 0;
	int warning = 0;
	bool force = false;

	peer = bgp_nb_config_peer(dir);
	if (!peer || !bgp_nb_dnode_afi_safi(dir, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	if (!yang_dnode_exists(dir, "./max-prefixes"))
		return NB_OK;

	max = yang_dnode_get_uint32(dir, "./max-prefixes");
	if (yang_dnode_exists(dir, "./force-check"))
		force = yang_dnode_get_bool(dir, "./force-check");

	if (yang_dnode_exists(dir, "./options/warning-only") &&
	    yang_dnode_get_bool(dir, "./options/warning-only")) {
		warning = 1;
	} else if (yang_dnode_exists(dir, "./options/restart-timer")) {
		restart = yang_dnode_get_uint16(dir, "./options/restart-timer");
	} else if (yang_dnode_exists(dir, "./options/shutdown-threshold-pct")) {
		threshold = yang_dnode_get_uint8(dir, "./options/shutdown-threshold-pct");
	} else if (yang_dnode_exists(dir, "./options/tr-shutdown-threshold-pct")) {
		threshold = yang_dnode_get_uint8(dir, "./options/tr-shutdown-threshold-pct");
		restart = yang_dnode_get_uint16(dir, "./options/tr-restart-timer");
	} else if (yang_dnode_exists(dir, "./options/tw-shutdown-threshold-pct")) {
		threshold = yang_dnode_get_uint8(dir, "./options/tw-shutdown-threshold-pct");
		warning = yang_dnode_exists(dir, "./options/tw-warning-only") &&
			  yang_dnode_get_bool(dir, "./options/tw-warning-only");
	}

	if (peer_maximum_prefix_set(peer, afi, safi, max, threshold, warning, restart, force) < 0)
		return NB_ERR_RESOURCE;
	return NB_OK;
}

static int bgp_nb_peer_af_max_prefix_out_apply(const struct lyd_node *dir)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	uint32_t max;

	peer = bgp_nb_config_peer(dir);
	if (!peer || !bgp_nb_dnode_afi_safi(dir, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	if (!yang_dnode_exists(dir, "./max-prefixes"))
		return NB_OK;

	max = yang_dnode_get_uint32(dir, "./max-prefixes");
	if (peer_maximum_prefix_out_set(peer, afi, safi, max) < 0)
		return NB_ERR_RESOURCE;
	return NB_OK;
}

static const struct lyd_node *bgp_nb_prefix_limit_dir(const struct lyd_node *dnode)
{
	return yang_dnode_get_parent(dnode, "direction-list");
}

int bgp_nb_peer_af_prefix_limit_create(struct nb_cb_create_args *args)
{
	const char *dir;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	dir = yang_dnode_get_string(args->dnode, "./direction");
	if (strmatch(dir, "in"))
		return bgp_nb_peer_af_max_prefix_in_apply(args->dnode);
	return bgp_nb_peer_af_max_prefix_out_apply(args->dnode);
}

int bgp_nb_peer_af_prefix_limit_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	const char *dir;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	dir = yang_dnode_get_string(args->dnode, "./direction");
	if (strmatch(dir, "in"))
		peer_maximum_prefix_unset(peer, afi, safi);
	else
		peer_maximum_prefix_out_unset(peer, afi, safi);
	return NB_OK;
}

int bgp_nb_peer_af_prefix_limit_max_modify(struct nb_cb_modify_args *args)
{
	const struct lyd_node *dir;
	const char *direction;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	dir = bgp_nb_prefix_limit_dir(args->dnode);
	if (!dir)
		return NB_ERR_NOT_FOUND;
	direction = yang_dnode_get_string(dir, "./direction");
	if (strmatch(direction, "in"))
		return bgp_nb_peer_af_max_prefix_in_apply(dir);
	return bgp_nb_peer_af_max_prefix_out_apply(dir);
}

int bgp_nb_peer_af_prefix_limit_force_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_prefix_limit_max_modify(args);
}

int bgp_nb_peer_af_prefix_limit_option_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_prefix_limit_max_modify(args);
}

int bgp_nb_peer_af_prefix_limit_option_destroy(struct nb_cb_destroy_args *args)
{
	const struct lyd_node *dir;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	dir = bgp_nb_prefix_limit_dir(args->dnode);
	if (!dir)
		return NB_OK;

	/* Re-apply remaining options after this leaf is gone. */
	if (strmatch(yang_dnode_get_string(dir, "./direction"), "in"))
		return bgp_nb_peer_af_max_prefix_in_apply(dir);
	return bgp_nb_peer_af_max_prefix_out_apply(dir);
}

void bgp_nb_cli_show_peer_af_prefix_limit_max(struct vty *vty, const struct lyd_node *dnode,
					      bool show_defaults)
{
	const struct lyd_node *dir = bgp_nb_prefix_limit_dir(dnode);
	const char *direction;
	uint32_t max;
	bool force = false;

	if (!dir)
		return;

	direction = yang_dnode_get_string(dir, "./direction");
	max = yang_dnode_get_uint32(dnode, NULL);
	if (yang_dnode_exists(dir, "./force-check"))
		force = yang_dnode_get_bool(dir, "./force-check");

	if (strmatch(direction, "out")) {
		vty_out(vty, "%sneighbor %s maximum-prefix-out %u\n",
			bgp_nb_peer_show_indent(dnode), bgp_nb_config_peer_name(dnode), max);
		return;
	}

	/*
	 * The neighbor name can be an arbitrarily long peer-group name, so
	 * emit the line piecewise instead of accumulating into a fixed
	 * size buffer.
	 */
	vty_out(vty, "%sneighbor %s maximum-prefix %u", bgp_nb_peer_show_indent(dnode),
		bgp_nb_config_peer_name(dnode), max);

	if (yang_dnode_exists(dir, "./options/tw-shutdown-threshold-pct")) {
		vty_out(vty, " %u",
			yang_dnode_get_uint8(dir, "./options/tw-shutdown-threshold-pct"));
		if (yang_dnode_exists(dir, "./options/tw-warning-only") &&
		    yang_dnode_get_bool(dir, "./options/tw-warning-only"))
			vty_out(vty, " warning-only");
	} else if (yang_dnode_exists(dir, "./options/tr-shutdown-threshold-pct")) {
		vty_out(vty, " %u restart %u",
			yang_dnode_get_uint8(dir, "./options/tr-shutdown-threshold-pct"),
			yang_dnode_get_uint16(dir, "./options/tr-restart-timer"));
	} else if (yang_dnode_exists(dir, "./options/shutdown-threshold-pct")) {
		vty_out(vty, " %u", yang_dnode_get_uint8(dir, "./options/shutdown-threshold-pct"));
	} else if (yang_dnode_exists(dir, "./options/restart-timer")) {
		vty_out(vty, " restart %u", yang_dnode_get_uint16(dir, "./options/restart-timer"));
	} else if (yang_dnode_exists(dir, "./options/warning-only") &&
		   yang_dnode_get_bool(dir, "./options/warning-only")) {
		vty_out(vty, " warning-only");
	}

	if (force)
		vty_out(vty, " force");

	vty_out(vty, "\n");
}

void bgp_nb_cli_show_peer_af_prefix_limit_noop(struct vty *vty, const struct lyd_node *dnode,
					       bool show_defaults)
{
	/* Rendered with max-prefixes cli_show. */
}

static void bgp_nb_peer_af_addpath_apply(struct peer *peer, afi_t afi, safi_t safi,
					 const struct lyd_node *addpaths)
{
	const char *type = "none";
	uint16_t paths = 0;
	enum bgp_addpath_strat strat = BGP_ADDPATH_NONE;

	if (yang_dnode_exists(addpaths, "./path-type"))
		type = yang_dnode_get_string(addpaths, "./path-type");

	if (strmatch(type, "all"))
		strat = BGP_ADDPATH_ALL;
	else if (strmatch(type, "per-as"))
		strat = BGP_ADDPATH_BEST_PER_AS;
	else if (strmatch(type, "best-selected")) {
		strat = BGP_ADDPATH_BEST_SELECTED;
		if (yang_dnode_exists(addpaths, "./best-selected-paths"))
			paths = yang_dnode_get_uint8(addpaths, "./best-selected-paths");
	} else
		strat = BGP_ADDPATH_NONE;

	bgp_addpath_set_peer_type(peer, afi, safi, strat, paths);
}

int bgp_nb_peer_af_addpath_type_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	const struct lyd_node *addpaths;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	addpaths = yang_dnode_get_parent(args->dnode, "add-paths");
	if (!addpaths)
		return NB_ERR_NOT_FOUND;

	bgp_nb_peer_af_addpath_apply(peer, afi, safi, addpaths);
	return NB_OK;
}

int bgp_nb_peer_af_addpath_best_selected_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_addpath_type_modify(args);
}

int bgp_nb_peer_af_addpath_best_selected_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	const struct lyd_node *addpaths;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	addpaths = yang_dnode_get_parent(args->dnode, "add-paths");
	if (!addpaths)
		return NB_OK;

	bgp_nb_peer_af_addpath_apply(peer, afi, safi, addpaths);
	return NB_OK;
}

void bgp_nb_cli_show_peer_af_addpath_type(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults)
{
	const char *type = yang_dnode_get_string(dnode, NULL);
	const struct lyd_node *addpaths = yang_dnode_get_parent(dnode, "add-paths");

	if (strmatch(type, "all"))
		vty_out(vty, "%sneighbor %s addpath-tx-all-paths\n",
			bgp_nb_peer_show_indent(dnode), bgp_nb_config_peer_name(dnode));
	else if (strmatch(type, "per-as"))
		vty_out(vty, "%sneighbor %s addpath-tx-bestpath-per-AS\n",
			bgp_nb_peer_show_indent(dnode), bgp_nb_config_peer_name(dnode));
	else if (strmatch(type, "best-selected") && addpaths &&
		 yang_dnode_exists(addpaths, "./best-selected-paths"))
		vty_out(vty, "%sneighbor %s addpath-tx-best-selected %u\n",
			bgp_nb_peer_show_indent(dnode), bgp_nb_config_peer_name(dnode),
			yang_dnode_get_uint8(addpaths, "./best-selected-paths"));
}

void bgp_nb_cli_show_peer_af_addpath_best_selected(struct vty *vty, const struct lyd_node *dnode,
						   bool show_defaults)
{
	/* Rendered with path-type cli_show. */
}

int bgp_nb_peer_af_disable_addpath_rx_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_af_flag_modify(args, PEER_FLAG_DISABLE_ADDPATH_RX);
}

void bgp_nb_cli_show_peer_af_disable_addpath_rx(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "%sneighbor %s disable-addpath-rx\n", bgp_nb_peer_show_indent(dnode),
			bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_af_addpath_rx_limit_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	uint16_t limit;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_ERR_NOT_FOUND;

	limit = yang_dnode_get_uint16(args->dnode, NULL);
	if (peer_af_flag_set(peer, afi, safi, PEER_FLAG_ADDPATH_RX_PATHS_LIMIT) < 0)
		return NB_ERR_RESOURCE;
	peer->addpath_paths_limit[afi][safi].send = limit;
	bgp_capability_send(peer->connection, afi, safi, CAPABILITY_CODE_PATHS_LIMIT,
			    CAPABILITY_ACTION_SET);
	return NB_OK;
}

int bgp_nb_peer_af_addpath_rx_limit_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer || !bgp_nb_dnode_afi_safi(args->dnode, &afi, &safi))
		return NB_OK;

	peer_af_flag_unset(peer, afi, safi, PEER_FLAG_ADDPATH_RX_PATHS_LIMIT);
	peer->addpath_paths_limit[afi][safi].send = 0;
	/*
	 * A tuple with zero Paths Limit is ignored by the receiver, so
	 * re-sending the capability alone would not clear the old limit.
	 * Withdraw the capability (clears all limits), and advertise it
	 * again with the limits still configured for other AFI/SAFIs.
	 */
	bgp_capability_send(peer->connection, afi, safi, CAPABILITY_CODE_PATHS_LIMIT,
			    CAPABILITY_ACTION_UNSET);
	bgp_capability_send(peer->connection, afi, safi, CAPABILITY_CODE_PATHS_LIMIT,
			    CAPABILITY_ACTION_SET);
	return NB_OK;
}

void bgp_nb_cli_show_peer_af_addpath_rx_limit(struct vty *vty, const struct lyd_node *dnode,
					      bool show_defaults)
{
	vty_out(vty, "%sneighbor %s addpath-rx-paths-limit %u\n", bgp_nb_peer_show_indent(dnode),
		bgp_nb_config_peer_name(dnode), yang_dnode_get_uint16(dnode, NULL));
}

static bool bgp_nb_path_attr_forbidden(uint8_t attr_num, struct peer *peer, char *errmsg,
				       size_t errmsg_len)
{
	if (attr_num == BGP_ATTR_ORIGIN || attr_num == BGP_ATTR_AS_PATH ||
	    attr_num == BGP_ATTR_NEXT_HOP || attr_num == BGP_ATTR_MULTI_EXIT_DISC ||
	    attr_num == BGP_ATTR_MP_REACH_NLRI || attr_num == BGP_ATTR_MP_UNREACH_NLRI ||
	    attr_num == BGP_ATTR_EXT_COMMUNITIES) {
		snprintfrr(errmsg, errmsg_len, "Can't discard/withdraw path-attribute %u",
			   attr_num);
		return true;
	}

	if (peer->sort != BGP_PEER_EBGP &&
	    (attr_num == BGP_ATTR_LOCAL_PREF || attr_num == BGP_ATTR_ORIGINATOR_ID ||
	     attr_num == BGP_ATTR_CLUSTER_LIST)) {
		snprintfrr(errmsg, errmsg_len, "path-attribute %u only valid for eBGP", attr_num);
		return true;
	}

	return false;
}

static void bgp_nb_peer_path_attr_soft_clear(struct peer *peer)
{
	afi_t afi;
	safi_t safi;

	FOREACH_AFI_SAFI (afi, safi)
		peer_clear_soft(peer, afi, safi, BGP_CLEAR_SOFT_IN);
}

/*
 * libyang sibling lists are circular: the first node's prev is the last
 * node, and yang_is_last_list_dnode() is true only for a one-element list.
 * Print once, from the first leaf-list entry of this name.
 */
static bool bgp_nb_leaflist_is_first(const struct lyd_node *dnode)
{
	const struct lyd_node *sib;

	if (!dnode)
		return false;

	sib = dnode->prev;
	while (sib && sib->next) {
		if (sib->schema && strmatch(sib->schema->name, dnode->schema->name))
			return false;
		if (!sib->prev || sib->prev == sib || sib->prev->next == NULL)
			break;
		sib = sib->prev;
	}
	return true;
}

static void bgp_nb_cli_show_peer_path_attr_list(struct vty *vty, const struct lyd_node *dnode,
						const char *leaf_name, const char *cli_kw)
{
	const struct lyd_node *parent, *child;

	if (!bgp_nb_leaflist_is_first(dnode))
		return;

	parent = lyd_parent(dnode);
	vty_out(vty, "%sneighbor %s path-attribute %s", bgp_nb_peer_show_indent(dnode),
		bgp_nb_config_peer_name(dnode), cli_kw);
	for (child = lyd_child(parent); child; child = child->next) {
		if (child->schema->nodetype != LYS_LEAFLIST)
			continue;
		if (!strmatch(child->schema->name, leaf_name))
			continue;
		vty_out(vty, " %u", yang_dnode_get_uint8(child, NULL));
	}
	vty_out(vty, "\n");
}

int bgp_nb_peer_path_attr_discard_create(struct nb_cb_create_args *args)
{
	struct peer *peer;
	uint8_t attr_num;

	switch (args->event) {
	case NB_EV_VALIDATE:
		peer = bgp_nb_config_peer(args->dnode);
		if (!peer)
			return NB_ERR_VALIDATION;
		attr_num = yang_dnode_get_uint8(args->dnode, NULL);
		if (bgp_nb_path_attr_forbidden(attr_num, peer, args->errmsg, args->errmsg_len))
			return NB_ERR_VALIDATION;
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	attr_num = yang_dnode_get_uint8(args->dnode, NULL);
	peer->discard_attrs[attr_num] = true;
	bgp_nb_peer_path_attr_soft_clear(peer);
	return NB_OK;
}

int bgp_nb_peer_path_attr_discard_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;
	uint8_t attr_num;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_OK;

	attr_num = yang_dnode_get_uint8(args->dnode, NULL);
	peer->discard_attrs[attr_num] = false;
	bgp_nb_peer_path_attr_soft_clear(peer);
	return NB_OK;
}

void bgp_nb_cli_show_peer_path_attr_discard(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults)
{
	bgp_nb_cli_show_peer_path_attr_list(vty, dnode, "discard", "discard");
}

int bgp_nb_peer_path_attr_withdraw_create(struct nb_cb_create_args *args)
{
	struct peer *peer;
	uint8_t attr_num;

	switch (args->event) {
	case NB_EV_VALIDATE:
		peer = bgp_nb_config_peer(args->dnode);
		if (!peer)
			return NB_ERR_VALIDATION;
		attr_num = yang_dnode_get_uint8(args->dnode, NULL);
		if (bgp_nb_path_attr_forbidden(attr_num, peer, args->errmsg, args->errmsg_len))
			return NB_ERR_VALIDATION;
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	attr_num = yang_dnode_get_uint8(args->dnode, NULL);
	peer->withdraw_attrs[attr_num] = true;
	bgp_nb_peer_path_attr_soft_clear(peer);
	return NB_OK;
}

int bgp_nb_peer_path_attr_withdraw_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;
	uint8_t attr_num;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_OK;

	attr_num = yang_dnode_get_uint8(args->dnode, NULL);
	peer->withdraw_attrs[attr_num] = false;
	bgp_nb_peer_path_attr_soft_clear(peer);
	return NB_OK;
}

void bgp_nb_cli_show_peer_path_attr_withdraw(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults)
{
	bgp_nb_cli_show_peer_path_attr_list(vty, dnode, "treat-as-withdraw", "treat-as-withdraw");
}

static int bgp_nb_peer_gr_cmd(struct peer *peer, enum peer_gr_command cmd)
{
	int result;
	int ret = BGP_GR_SUCCESS;

	result = bgp_neighbor_graceful_restart(peer, cmd);
	if (result == BGP_GR_SUCCESS)
		VTY_BGP_GR_ROUTER_DETECT_AND_SEND_CAPABILITY_TO_ZEBRA(peer->bgp, peer->bgp->peer,
								      ret);

	if (result == BGP_GR_FAILURE || ret == BGP_ERR_INVALID_VALUE)
		return NB_ERR_RESOURCE;
	return NB_OK;
}

int bgp_nb_peer_gr_enable_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	if (yang_dnode_get_bool(args->dnode, NULL))
		return bgp_nb_peer_gr_cmd(peer, PEER_GR_CMD);
	return bgp_nb_peer_gr_cmd(peer, NO_PEER_GR_CMD);
}

int bgp_nb_peer_gr_enable_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_OK;

	return bgp_nb_peer_gr_cmd(peer, NO_PEER_GR_CMD);
}

void bgp_nb_cli_show_peer_gr_enable(struct vty *vty, const struct lyd_node *dnode,
				    bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "%sneighbor %s graceful-restart\n", bgp_nb_peer_show_indent(dnode),
			bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_gr_helper_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	if (yang_dnode_get_bool(args->dnode, NULL))
		return bgp_nb_peer_gr_cmd(peer, PEER_HELPER_CMD);
	return bgp_nb_peer_gr_cmd(peer, NO_PEER_HELPER_CMD);
}

int bgp_nb_peer_gr_helper_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_OK;

	return bgp_nb_peer_gr_cmd(peer, NO_PEER_HELPER_CMD);
}

void bgp_nb_cli_show_peer_gr_helper(struct vty *vty, const struct lyd_node *dnode,
				    bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "%sneighbor %s graceful-restart-helper\n",
			bgp_nb_peer_show_indent(dnode), bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_gr_disable_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	if (yang_dnode_get_bool(args->dnode, NULL))
		return bgp_nb_peer_gr_cmd(peer, PEER_DISABLE_CMD);
	return bgp_nb_peer_gr_cmd(peer, NO_PEER_DISABLE_CMD);
}

int bgp_nb_peer_gr_disable_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_OK;

	return bgp_nb_peer_gr_cmd(peer, NO_PEER_DISABLE_CMD);
}

void bgp_nb_cli_show_peer_gr_disable(struct vty *vty, const struct lyd_node *dnode,
				     bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "%sneighbor %s graceful-restart-disable\n",
			bgp_nb_peer_show_indent(dnode), bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_aigp_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_flag_set(peer, PEER_FLAG_AIGP);
	else
		peer_flag_unset(peer, PEER_FLAG_AIGP);
	return NB_OK;
}

void bgp_nb_cli_show_peer_aigp(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s aigp\n", bgp_nb_config_peer_name(dnode));
	else if (show_defaults)
		vty_out(vty, " no neighbor %s aigp\n", bgp_nb_config_peer_name(dnode));
}

int bgp_nb_peer_oad_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	if (yang_dnode_get_bool(args->dnode, NULL)) {
		if (peer->sort == BGP_PEER_EBGP)
			peer->sub_sort = BGP_PEER_EBGP_OAD;
	} else
		peer->sub_sort = 0;
	return NB_OK;
}

void bgp_nb_cli_show_peer_oad(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, "%sneighbor %s oad\n", bgp_nb_peer_show_indent(dnode),
			bgp_nb_config_peer_name(dnode));
	else if (show_defaults)
		vty_out(vty, "%sno neighbor %s oad\n", bgp_nb_peer_show_indent(dnode),
			bgp_nb_config_peer_name(dnode));
}

static void bgp_nb_peer_announce_routes(struct peer *peer)
{
	afi_t afi;
	safi_t safi;
	struct peer_af *paf;

	FOREACH_AFI_SAFI (afi, safi) {
		if (!peer->afc[afi][safi])
			continue;
		paf = peer_af_find(peer, afi, safi);
		if (paf) {
			update_group_adjust_peer(paf);
			bgp_announce_route(peer, afi, safi, false);
		}
	}
}

static void bgp_nb_peer_gs_soft_reset(struct peer *peer)
{
	struct listnode *node, *nnode;
	struct peer *member;
	afi_t afi;
	safi_t safi;

	/*
	 * Match classic neighbor graceful-shutdown: soft-in clear plus
	 * re-announce so originated routes pick up/drop GSHUT / loc-pref 0.
	 */
	if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		for (ALL_LIST_ELEMENTS(peer->group->peer, node, nnode, member)) {
			FOREACH_AFI_SAFI (afi, safi)
				peer_clear_soft(member, afi, safi, BGP_CLEAR_SOFT_IN);
			bgp_nb_peer_announce_routes(member);
		}
	} else {
		FOREACH_AFI_SAFI (afi, safi)
			peer_clear_soft(peer, afi, safi, BGP_CLEAR_SOFT_IN);
		bgp_nb_peer_announce_routes(peer);
	}
}

int bgp_nb_peer_graceful_shutdown_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	int ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_config_peer(args->dnode);
	if (!peer)
		return NB_ERR_NOT_FOUND;

	if (yang_dnode_get_bool(args->dnode, NULL))
		ret = peer_flag_set(peer, PEER_FLAG_GRACEFUL_SHUTDOWN);
	else
		ret = peer_flag_unset(peer, PEER_FLAG_GRACEFUL_SHUTDOWN);

	if (ret == 0)
		bgp_nb_peer_gs_soft_reset(peer);
	else if (ret < 0)
		return NB_ERR_RESOURCE;
	return NB_OK;
}

void bgp_nb_cli_show_peer_graceful_shutdown(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s graceful-shutdown\n", bgp_nb_config_peer_name(dnode));
	else if (show_defaults)
		vty_out(vty, " no neighbor %s graceful-shutdown\n", bgp_nb_config_peer_name(dnode));
}
