/*
 * Bgp northbound config callbacks
 * Copyright (C) 2020  Nvidia
 *		       Chirag Shah
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "northbound.h"
#include "libfrr.h"
#include "log.h"
#include "bgpd/bgp_nb.h"
#include "bgpd/bgp_nb.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_addpath.h"
#include "bgpd/bgp_updgrp.h"
#include "bgpd/bgp_io.h"
#include "bgpd/bgp_damp.h"

FRR_CFG_DEFAULT_ULONG(BGP_CONNECT_RETRY,
        { .val_ulong = 10, .match_profile = "datacenter", },
        { .val_ulong = 120 },
)
FRR_CFG_DEFAULT_ULONG(BGP_HOLDTIME,
        { .val_ulong = 9, .match_profile = "datacenter", },
        { .val_ulong = 180 },
)
FRR_CFG_DEFAULT_ULONG(BGP_KEEPALIVE,
        { .val_ulong = 3, .match_profile = "datacenter", },
        { .val_ulong = 60 },
)

int routing_control_plane_protocols_name_validate(
	struct nb_cb_create_args *args)
{
	const char *name;

	name = yang_dnode_get_string(args->dnode, "./name");
	if (!strmatch(name, "bgp")) {
		snprintf(args->errmsg, args->errmsg_len,
			 "per vrf only one bgp instance is supported.");
		return NB_ERR_VALIDATION;
	}
	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp
 */
int bgp_router_create(struct nb_cb_create_args *args)
{
	const struct lyd_node *vrf_dnode;
	struct bgp *bgp;
	struct vrf *vrf;
	const char *name = NULL;
	as_t as;
	enum bgp_instance_type inst_type;
	bool is_view_inst = false;
	int ret;
	int is_new_bgp = 0;

	inst_type = BGP_INSTANCE_TYPE_DEFAULT;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		vrf_dnode = yang_dnode_get_parent(args->dnode,
						  "control-plane-protocol");
		vrf = nb_running_get_entry(vrf_dnode, NULL, true);

		if (strmatch(vrf->name, VRF_DEFAULT_NAME)) {
			name = NULL;
		} else {
			name = vrf->name;
			inst_type = BGP_INSTANCE_TYPE_VRF;
		}

		as = yang_dnode_get_uint32(args->dnode, "./global/local-as");

		is_view_inst = yang_dnode_get_bool(
			args->dnode, "./global/instance-type-view");
		if (is_view_inst)
			inst_type = BGP_INSTANCE_TYPE_VIEW;

		if (inst_type == BGP_INSTANCE_TYPE_DEFAULT)
			is_new_bgp = (bgp_lookup(as, name) == NULL);

		ret = bgp_get_vty(&bgp, &as, name, inst_type);
		if (ret == BGP_ERR_INSTANCE_MISMATCH) {
			snprintf(
				args->errmsg, args->errmsg_len,
				"BGP instance name and AS number mismatch\nBGP instance is already running; AS is %u, input-as %u",
				bgp->as, as);

			return NB_ERR_INCONSISTENCY;
		}
		/*
		 * If we just instantiated the default instance, complete
		 * any pending VRF-VPN leaking that was configured via
		 * earlier "router bgp X vrf FOO" blocks.
		 */
		if (is_new_bgp && inst_type == BGP_INSTANCE_TYPE_DEFAULT)
			vpn_leak_postchange_all();

		if (inst_type == BGP_INSTANCE_TYPE_VRF)
			bgp_vpn_leak_export(bgp);

		UNSET_FLAG(bgp->vrf_flags, BGP_VRF_AUTO);

		nb_running_set_entry(args->dnode, bgp);
		break;
	}

	return NB_OK;
}

int bgp_router_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
		bgp = nb_running_get_entry(args->dnode, NULL, false);

		if (!bgp)
			return NB_OK;

		if (bgp->l3vni) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Please unconfigure l3vni %u", bgp->l3vni);
			return NB_ERR_VALIDATION;
		}

		/* Cannot delete default instance if vrf instances exist */
		if (bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT) {
			struct listnode *node;
			struct bgp *tmp_bgp;

			for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, tmp_bgp)) {
				if (tmp_bgp->inst_type
				    == BGP_INSTANCE_TYPE_VRF) {
					snprintf(
						args->errmsg, args->errmsg_len,
						"Cannot delete default BGP instance. Dependent VRF instances exist\n");
					return NB_ERR_VALIDATION;
				}
			}
		}

		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_unset_entry(args->dnode);

		bgp_delete(bgp);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/local-as
 */
int bgp_global_local_as_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	as_t as;
	const struct lyd_node *vrf_dnode;
	const char *vrf_name;
	const char *name = NULL;
	enum bgp_instance_type inst_type;
	int ret;
	bool is_view_inst = false;

	switch (args->event) {
	case NB_EV_VALIDATE:
		as = yang_dnode_get_uint32(args->dnode, NULL);

		inst_type = BGP_INSTANCE_TYPE_DEFAULT;

		vrf_dnode = yang_dnode_get_parent(args->dnode,
						  "control-plane-protocol");
		vrf_name = yang_dnode_get_string(vrf_dnode, "./vrf");

		if (strmatch(vrf_name, VRF_DEFAULT_NAME)) {
			name = NULL;
		} else {
			name = vrf_name;
			inst_type = BGP_INSTANCE_TYPE_VRF;
		}

		is_view_inst = yang_dnode_get_bool(args->dnode,
						   "../instance-type-view");
		if (is_view_inst)
			inst_type = BGP_INSTANCE_TYPE_VIEW;

		ret = bgp_lookup_by_as_name_type(&bgp, &as, name, inst_type);
		if (ret == BGP_ERR_INSTANCE_MISMATCH) {
			snprintf(
				args->errmsg, args->errmsg_len,
				"BGP instance name and AS number mismatch\nBGP instance is already running; input-as %u",
				as);

			return NB_ERR_VALIDATION;
		}

		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		/* NOTE: handled in bgp_global_create callback, the as change
		 * will be rejected in validate phase.
		 */
		as = yang_dnode_get_uint32(args->dnode, NULL);
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		if (bgp->as != as) {
			snprintf(args->errmsg, args->errmsg_len,
				 "BGP instance is already running; AS is %u",
				 bgp->as);
			return NB_ERR_INCONSISTENCY;
		}
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/router-id
 */
int bgp_global_router_id_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	struct bgp *bgp;
	struct in_addr router_id;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	yang_dnode_get_ipv4(&router_id, args->dnode, NULL);
	bgp_router_id_static_set(bgp, router_id);

	return NB_OK;
}

int bgp_global_router_id_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	struct bgp *bgp;
	struct in_addr router_id;

	bgp = nb_running_get_entry(args->dnode, NULL, true);

	router_id.s_addr = 0;
	bgp_router_id_static_set(bgp, router_id);

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/confederation/identifier
 */
int bgp_global_confederation_identifier_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	as_t as;

	switch (args->event) {
	case NB_EV_VALIDATE:
		as = yang_dnode_get_uint32(args->dnode, NULL);
		if (!as) {
			snprintf(args->errmsg, args->errmsg_len, "Invalid AS.");
			return NB_ERR_VALIDATION;
		}

		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);

		as = yang_dnode_get_uint32(args->dnode, NULL);

		bgp_confederation_id_set(bgp, as);

		break;
	}

	return NB_OK;
}

int bgp_global_confederation_identifier_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	struct bgp *bgp;

	bgp = nb_running_get_entry(args->dnode, NULL, true);

	bgp_confederation_id_unset(bgp);

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/confederation/member-as
 */
int bgp_global_confederation_member_as_create(struct nb_cb_create_args *args)
{
	as_t my_as, as;
	struct bgp *bgp;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
		my_as = yang_dnode_get_uint32(args->dnode,
					      "../../../global/local-as");
		as = yang_dnode_get_uint32(args->dnode, NULL);
		if (my_as == as) {
			snprintf(
				args->errmsg, args->errmsg_len,
				"Local member-AS %u not allowed in confed peer list",
				my_as);
			return NB_ERR_VALIDATION;
		}

		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		as = yang_dnode_get_uint32(args->dnode, NULL);

		ret = bgp_confederation_peers_add(bgp, as);
		if (ret == BGP_ERR_INVALID_AS) {
			snprintf(
				args->errmsg, args->errmsg_len,
				"Local member-AS not alloed in confed peer list");
			return NB_ERR_INCONSISTENCY;
		}

		break;
	}

	return NB_OK;
}

int bgp_global_confederation_member_as_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	as_t as;
	struct bgp *bgp;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	as = yang_dnode_get_uint32(args->dnode, NULL);

	bgp_confederation_peers_remove(bgp, as);

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/med-config
 */
void bgp_global_med_config_apply_finish(struct nb_cb_apply_finish_args *args)
{
	struct bgp *bgp;

	bgp = nb_running_get_entry(args->dnode, NULL, true);

	bgp_maxmed_update(bgp);
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/med-config/enable-med-admin
 */
int bgp_global_med_config_enable_med_admin_modify(
	struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	struct bgp *bgp;

	bgp = nb_running_get_entry(args->dnode, NULL, true);

	bgp->v_maxmed_admin = yang_dnode_get_bool(args->dnode, NULL);

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/med-config/max-med-admin
 */
int bgp_global_med_config_max_med_admin_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	uint32_t med_admin_val;

	switch (args->event) {
	case NB_EV_VALIDATE:
		med_admin_val = yang_dnode_get_uint32(args->dnode, NULL);

		/* enable_med_admin is required to be enabled for max-med-admin
		 * non default value.
		 */
		if (med_admin_val != BGP_MAXMED_VALUE_DEFAULT
		    && !yang_dnode_get_bool(args->dnode,
					    "../enable-med-admin")) {
			snprintf(args->errmsg, args->errmsg_len,
				 "enable med admin is not set");
			return NB_ERR_VALIDATION;
		}

		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);

		med_admin_val = yang_dnode_get_uint32(args->dnode, NULL);

		bgp->maxmed_admin_value = med_admin_val;

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/med-config/max-med-onstart-up-time
 */
int bgp_global_med_config_max_med_onstart_up_time_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);

		bgp->v_maxmed_onstartup =
			yang_dnode_get_uint32(args->dnode, NULL);

		break;
	}

	return NB_OK;
}

int bgp_global_med_config_max_med_onstart_up_time_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);

		/* Cancel max-med onstartup if its on */
		if (bgp->t_maxmed_onstartup) {
			THREAD_OFF(bgp->t_maxmed_onstartup);
			bgp->maxmed_onstartup_over = 1;
		}

		bgp->v_maxmed_onstartup = BGP_MAXMED_ONSTARTUP_UNCONFIGURED;
		/* Resetting onstartup value as part of dependent node is
		 * detroyed.
		 */
		bgp->maxmed_onstartup_value = BGP_MAXMED_VALUE_DEFAULT;

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/med-config/max-med-onstart-up-value
 */
int bgp_global_med_config_max_med_onstart_up_value_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	uint32_t onstartup_val;

	switch (args->event) {
	case NB_EV_VALIDATE:
		onstartup_val = yang_dnode_get_uint32(args->dnode, NULL);

		if (!yang_dnode_exists(args->dnode,
				       "../max-med-onstart-up-time")
		    && onstartup_val != BGP_MAXMED_VALUE_DEFAULT) {
			snprintf(args->errmsg, args->errmsg_len,
				 "max-med-onstart-up-time is not set.");
			return NB_ERR_VALIDATION;
		}

		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);

		bgp->maxmed_onstartup_value =
			yang_dnode_get_uint32(args->dnode, NULL);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-reflector/route-reflector-cluster-id
 */
int bgp_global_route_reflector_route_reflector_cluster_id_modify(
	struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	struct bgp *bgp;
	struct in_addr cluster_id;
	const struct lyd_node_leaf_list *dleaf;

	bgp = nb_running_get_entry(args->dnode, NULL, true);

	dleaf = (const struct lyd_node_leaf_list *)args->dnode;
	if (dleaf->value_type == LY_TYPE_STRING)
		yang_dnode_get_ipv4(&cluster_id, args->dnode, NULL);
	else
		(void)inet_aton(dleaf->value_str, &cluster_id);

	bgp_cluster_id_set(bgp, &cluster_id);

	if (bgp_clear_star_soft_out(bgp->name, args->errmsg, args->errmsg_len))
		return NB_ERR_INCONSISTENCY;

	return NB_OK;
}

int bgp_global_route_reflector_route_reflector_cluster_id_destroy(
	struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	struct bgp *bgp;

	bgp = nb_running_get_entry(args->dnode, NULL, true);

	bgp_cluster_id_unset(bgp);

	if (bgp_clear_star_soft_out(bgp->name, args->errmsg, args->errmsg_len))
		return NB_ERR_INCONSISTENCY;

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-reflector/no-client-reflect
 */
int bgp_global_route_reflector_no_client_reflect_modify(
	struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	struct bgp *bgp;

	bgp = nb_running_get_entry(args->dnode, NULL, true);

	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_NO_CLIENT_TO_CLIENT);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_NO_CLIENT_TO_CLIENT);

	if (bgp_clear_star_soft_out(bgp->name, args->errmsg, args->errmsg_len))
		return NB_ERR_INCONSISTENCY;

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-reflector/allow-outbound-policy
 */
int bgp_global_route_reflector_allow_outbound_policy_modify(
	struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	struct bgp *bgp;

	bgp = nb_running_get_entry(args->dnode, NULL, true);

	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_RR_ALLOW_OUTBOUND_POLICY);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_RR_ALLOW_OUTBOUND_POLICY);

	update_group_announce_rrclients(bgp);

	if (bgp_clear_star_soft_out(bgp->name, args->errmsg, args->errmsg_len))
		return NB_ERR_INCONSISTENCY;

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options
 */
void bgp_global_route_selection_options_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	struct bgp *bgp;

	bgp = nb_running_get_entry(args->dnode, NULL, true);

	bgp_recalculate_all_bestpaths(bgp);
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/always-compare-med
 */
int bgp_global_route_selection_options_always_compare_med_modify(
	struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	struct bgp *bgp;

	bgp = nb_running_get_entry(args->dnode, NULL, true);

	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_ALWAYS_COMPARE_MED);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_ALWAYS_COMPARE_MED);


	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/deterministic-med
 */
int bgp_global_route_selection_options_deterministic_med_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	int bestpath_per_as_used;
	afi_t afi;
	safi_t safi;
	struct peer *peer;
	struct listnode *node;

	switch (args->event) {
	case NB_EV_VALIDATE:
		bgp = nb_running_get_entry(args->dnode, NULL, false);

		if (!bgp)
			return NB_OK;

		/* for deconfiguring deterministic-med case */
		if (!yang_dnode_get_bool(args->dnode, NULL)
		    && CHECK_FLAG(bgp->flags, BGP_FLAG_DETERMINISTIC_MED)) {
			bestpath_per_as_used = 0;

			for (ALL_LIST_ELEMENTS_RO(bgp->peer, node, peer)) {
				FOREACH_AFI_SAFI (afi, safi)
					if (bgp_addpath_dmed_required(
						    peer->addpath_type[afi]
								      [safi])) {
						bestpath_per_as_used = 1;
						break;
					}

				if (bestpath_per_as_used)
					break;
			}

			if (bestpath_per_as_used) {
				snprintf(
					args->errmsg, args->errmsg_len,
					"bgp deterministic-med cannot be disabled while addpath-tx-bestpath-per-AS is in use");
				return NB_ERR_VALIDATION;
			}
		}

		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);

		if (yang_dnode_get_bool(args->dnode, NULL))
			SET_FLAG(bgp->flags, BGP_FLAG_DETERMINISTIC_MED);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_DETERMINISTIC_MED);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/confed-med
 */
int bgp_global_route_selection_options_confed_med_modify(
	struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	struct bgp *bgp;

	bgp = nb_running_get_entry(args->dnode, NULL, true);

	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_MED_CONFED);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_MED_CONFED);

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/missing-as-worst-med
 */
int bgp_global_route_selection_options_missing_as_worst_med_modify(
	struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	struct bgp *bgp;

	bgp = nb_running_get_entry(args->dnode, NULL, true);

	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_MED_MISSING_AS_WORST);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_MED_MISSING_AS_WORST);

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/aspath-confed
 */
int bgp_global_route_selection_options_aspath_confed_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/ignore-as-path-length
 */
int bgp_global_route_selection_options_ignore_as_path_length_modify(
	struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	struct bgp *bgp;

	bgp = nb_running_get_entry(args->dnode, NULL, true);

	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_ASPATH_IGNORE);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_ASPATH_IGNORE);

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/external-compare-router-id
 */
int bgp_global_route_selection_options_external_compare_router_id_modify(
	struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	struct bgp *bgp;

	bgp = nb_running_get_entry(args->dnode, NULL, true);

	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_COMPARE_ROUTER_ID);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_COMPARE_ROUTER_ID);

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/allow-multiple-as
 */
int bgp_global_route_selection_options_allow_multiple_as_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);

		if (yang_dnode_get_bool(args->dnode, NULL)) {
			SET_FLAG(bgp->flags, BGP_FLAG_ASPATH_MULTIPATH_RELAX);
			if (yang_dnode_get_bool(args->dnode,
						"../multi-path-as-set")) {
				SET_FLAG(bgp->flags,
					 BGP_FLAG_MULTIPATH_RELAX_AS_SET);
			}
		} else {
			UNSET_FLAG(bgp->flags, BGP_FLAG_ASPATH_MULTIPATH_RELAX);
			/* unset as-set */
			UNSET_FLAG(bgp->flags, BGP_FLAG_MULTIPATH_RELAX_AS_SET);
		}

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/route-selection-options/multi-path-as-set
 */
int bgp_global_route_selection_options_multi_path_as_set_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);

		if (!CHECK_FLAG(bgp->flags, BGP_FLAG_MULTIPATH_RELAX_AS_SET)) {
			SET_FLAG(bgp->flags, BGP_FLAG_MULTIPATH_RELAX_AS_SET);

		} else
			zlog_debug(
				"%s multi-path-as-set as part of allow-multiple-as modify cb.",
				__func__);

		break;
	}

	return NB_OK;
}

int bgp_global_route_selection_options_multi_path_as_set_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		/* Only unset if it set, it is possible allow_multiple_as_modify
		 * unset this.
		 */
		if (CHECK_FLAG(bgp->flags, BGP_FLAG_MULTIPATH_RELAX_AS_SET)) {
			UNSET_FLAG(bgp->flags, BGP_FLAG_MULTIPATH_RELAX_AS_SET);

			bgp_recalculate_all_bestpaths(bgp);
		}

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-neighbor-config/dynamic-neighbors-limit
 */
int bgp_global_global_neighbor_config_dynamic_neighbors_limit_modify(
	struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	struct bgp *bgp;
	uint32_t listen_limit;

	bgp = nb_running_get_entry(args->dnode, NULL, true);

	listen_limit = yang_dnode_get_uint32(args->dnode, NULL);

	bgp_listen_limit_set(bgp, listen_limit);

	return NB_OK;
}

int bgp_global_global_neighbor_config_dynamic_neighbors_limit_destroy(
	struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	struct bgp *bgp;

	bgp = nb_running_get_entry(args->dnode, NULL, true);

	bgp_listen_limit_unset(bgp);

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-neighbor-config/log-neighbor-changes
 */
int bgp_global_global_neighbor_config_log_neighbor_changes_modify(
	struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	struct bgp *bgp;

	bgp = nb_running_get_entry(args->dnode, NULL, true);

	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_LOG_NEIGHBOR_CHANGES);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_LOG_NEIGHBOR_CHANGES);

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-neighbor-config/packet-quanta-config/wpkt-quanta
 */
int bgp_global_global_neighbor_config_packet_quanta_config_wpkt_quanta_modify(
	struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	struct bgp *bgp;
	uint32_t quanta;

	bgp = nb_running_get_entry(args->dnode, NULL, true);

	quanta = yang_dnode_get_uint32(args->dnode, NULL);

	if (atomic_load_explicit(&bgp->wpkt_quanta, memory_order_relaxed)
	    == BGP_WRITE_PACKET_MAX)
		bgp_wpkt_quanta_config_vty(bgp, quanta, true);
	else
		bgp_wpkt_quanta_config_vty(bgp, quanta, false);

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-neighbor-config/packet-quanta-config/rpkt-quanta
 */
int bgp_global_global_neighbor_config_packet_quanta_config_rpkt_quanta_modify(
	struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	struct bgp *bgp;
	uint32_t quanta;

	bgp = nb_running_get_entry(args->dnode, NULL, true);

	quanta = yang_dnode_get_uint32(args->dnode, NULL);

	if (atomic_load_explicit(&bgp->rpkt_quanta, memory_order_relaxed)
	    == BGP_READ_PACKET_MAX)
		bgp_rpkt_quanta_config_vty(bgp, quanta, true);
	else
		bgp_rpkt_quanta_config_vty(bgp, quanta, false);

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/graceful-restart/enabled
 */
int bgp_global_graceful_restart_enabled_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_graceful_restart_enabled_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/graceful-restart/graceful-restart-disable
 */
int bgp_global_graceful_restart_graceful_restart_disable_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_graceful_restart_graceful_restart_disable_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/graceful-restart/preserve-fw-entry
 */
int bgp_global_graceful_restart_preserve_fw_entry_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/graceful-restart/restart-time
 */
int bgp_global_graceful_restart_restart_time_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/graceful-restart/stale-routes-time
 */
int bgp_global_graceful_restart_stale_routes_time_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/graceful-restart/selection-deferral-time
 */
int bgp_global_graceful_restart_selection_deferral_time_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/graceful-restart/rib-stale-time
 */
int bgp_global_graceful_restart_rib_stale_time_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-update-group-config/subgroup-pkt-queue-size
 */
int bgp_global_global_update_group_config_subgroup_pkt_queue_size_modify(
	struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	struct bgp *bgp;
	uint32_t max_size;

	bgp = nb_running_get_entry(args->dnode, NULL, true);

	max_size = yang_dnode_get_uint32(args->dnode, NULL);

	bgp_default_subgroup_pkt_queue_max_set(bgp, max_size);

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-update-group-config/coalesce-time
 */
int bgp_global_global_update_group_config_coalesce_time_modify(
	struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	struct bgp *bgp;
	uint32_t coalesce_time;

	bgp = nb_running_get_entry(args->dnode, NULL, true);

	coalesce_time = yang_dnode_get_uint32(args->dnode, NULL);

	if (coalesce_time != BGP_DEFAULT_SUBGROUP_COALESCE_TIME) {
		bgp->heuristic_coalesce = false;
		bgp->coalesce_time = coalesce_time;
	} else {
		bgp->heuristic_coalesce = true;
		bgp->coalesce_time = BGP_DEFAULT_SUBGROUP_COALESCE_TIME;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-config-timers/rmap-delay-time
 */
int bgp_global_global_config_timers_rmap_delay_time_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-config-timers/update-delay-time
 */
int bgp_global_global_config_timers_update_delay_time_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_global_config_timers_update_delay_time_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-config-timers/establish-wait-time
 */
int bgp_global_global_config_timers_establish_wait_time_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_global_config_timers_establish_wait_time_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-config-timers/connect-retry-interval
 */
int bgp_global_global_config_timers_connect_retry_interval_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-config-timers/hold-time
 */
int bgp_global_global_config_timers_hold_time_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	unsigned long keepalive = 0;
	unsigned long holdtime = 0;

	switch (args->event) {
	case NB_EV_VALIDATE:
		holdtime = yang_dnode_get_uint16(args->dnode, NULL);
		/* Holdtime value check. */
		if (holdtime < 3 && holdtime != 0) {
			snprintf(
				args->errmsg, args->errmsg_len,
				"hold time value must be either 0 or greater than 3");
			return NB_ERR_VALIDATION;
		}

		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);

		keepalive = yang_dnode_get_uint16(args->dnode, "../keepalive");
		holdtime = yang_dnode_get_uint16(args->dnode, NULL);

		bgp_timers_set(bgp, keepalive, holdtime, DFLT_BGP_CONNECT_RETRY,
			       BGP_DEFAULT_DELAYOPEN);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/global-config-timers/keepalive
 */
int bgp_global_global_config_timers_keepalive_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	unsigned long keepalive = 0;
	unsigned long holdtime = 0;

	switch (args->event) {
	case NB_EV_VALIDATE:
		holdtime = yang_dnode_get_uint16(args->dnode, "../hold-time");
		/* Holdtime value check. */
		if (holdtime < 3 && holdtime != 0) {
			snprintf(
				args->errmsg, args->errmsg_len,
				"hold time value must be either 0 or greater than 3");
			return NB_ERR_VALIDATION;
		}

		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);

		keepalive = yang_dnode_get_uint16(args->dnode, NULL);
		holdtime = yang_dnode_get_uint16(args->dnode, "../hold-time");

		bgp_timers_set(bgp, keepalive, holdtime, DFLT_BGP_CONNECT_RETRY,
			       BGP_DEFAULT_DELAYOPEN);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/instance-type-view
 */
int bgp_global_instance_type_view_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/ebgp-multihop-connected-route-check
 */
int bgp_global_ebgp_multihop_connected_route_check_modify(
	struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	struct bgp *bgp;

	bgp = nb_running_get_entry(args->dnode, NULL, true);

	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_DISABLE_NH_CONNECTED_CHK);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_DISABLE_NH_CONNECTED_CHK);

	if (bgp_clear_star_soft_in(bgp->name, args->errmsg, args->errmsg_len))
		return NB_ERR_INCONSISTENCY;

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/fast-external-failover
 */
int bgp_global_fast_external_failover_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	struct bgp *bgp;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	if (!yang_dnode_get_bool(args->dnode, NULL)) {
		SET_FLAG(bgp->flags, BGP_FLAG_NO_FAST_EXT_FAILOVER);
	} else
		UNSET_FLAG(bgp->flags, BGP_FLAG_NO_FAST_EXT_FAILOVER);

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/local-pref
 */
int bgp_global_local_pref_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	struct bgp *bgp;
	uint32_t local_pref;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	local_pref = yang_dnode_get_uint32(args->dnode, NULL);

	bgp_default_local_preference_set(bgp, local_pref);

	if (bgp_clear_star_soft_in(bgp->name, args->errmsg, args->errmsg_len))
		return NB_ERR_INCONSISTENCY;

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/default-shutdown
 */
int bgp_global_default_shutdown_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	struct bgp *bgp;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	bgp->autoshutdown = yang_dnode_get_bool(args->dnode, NULL);

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/ebgp-requires-policy
 */
int bgp_global_ebgp_requires_policy_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	struct bgp *bgp;

	bgp = nb_running_get_entry(args->dnode, NULL, true);

	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_EBGP_REQUIRES_POLICY);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_EBGP_REQUIRES_POLICY);

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/suppress-duplicates
 */
int bgp_global_suppress_duplicates_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	struct bgp *bgp;

	bgp = nb_running_get_entry(args->dnode, NULL, true);

	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_SUPPRESS_DUPLICATES);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_SUPPRESS_DUPLICATES);

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/show-hostname
 */
int bgp_global_show_hostname_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	struct bgp *bgp;

	bgp = nb_running_get_entry(args->dnode, NULL, true);

	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_SHOW_HOSTNAME);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_SHOW_HOSTNAME);

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/show-nexthop-hostname
 */
int bgp_global_show_nexthop_hostname_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	struct bgp *bgp;

	bgp = nb_running_get_entry(args->dnode, NULL, true);

	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_SHOW_NEXTHOP_HOSTNAME);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_SHOW_NEXTHOP_HOSTNAME);

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/import-check
 */
int bgp_global_import_check_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	struct bgp *bgp;

	bgp = nb_running_get_entry(args->dnode, NULL, true);

	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_IMPORT_CHECK);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_IMPORT_CHECK);

	bgp_static_redo_import_check(bgp);

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/graceful-shutdown/enable
 */
int bgp_global_graceful_shutdown_enable_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (CHECK_FLAG(bm->flags, BM_FLAG_GRACEFUL_SHUTDOWN)) {
			snprintf(
				args->errmsg, args->errmsg_len,
				"%%Failed: per-vrf graceful-shutdown config not permitted with global graceful-shutdown");
			return NB_ERR_VALIDATION;
		}

		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);

		if (yang_dnode_get_bool(args->dnode, NULL))
			SET_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_SHUTDOWN);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_SHUTDOWN);

		bgp_static_redo_import_check(bgp);
		bgp_redistribute_redo(bgp);

		if (bgp_clear_star_soft_out(bgp->name, args->errmsg,
					    args->errmsg_len))
			return NB_ERR_INCONSISTENCY;

		if (bgp_clear_star_soft_in(bgp->name, args->errmsg,
					   args->errmsg_len))
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list
 */
int bgp_global_bmp_config_target_list_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_bmp_config_target_list_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/incoming-session/session-list
 */
int bgp_global_bmp_config_target_list_incoming_session_session_list_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_bmp_config_target_list_incoming_session_session_list_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/outgoing-session/session-list
 */
int bgp_global_bmp_config_target_list_outgoing_session_session_list_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_bmp_config_target_list_outgoing_session_session_list_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/outgoing-session/session-list/min-retry-time
 */
int bgp_global_bmp_config_target_list_outgoing_session_session_list_min_retry_time_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/outgoing-session/session-list/max-retry-time
 */
int bgp_global_bmp_config_target_list_outgoing_session_session_list_max_retry_time_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/mirror
 */
int bgp_global_bmp_config_target_list_mirror_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/stats-time
 */
int bgp_global_bmp_config_target_list_stats_time_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_bmp_config_target_list_stats_time_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/ipv4-access-list
 */
int bgp_global_bmp_config_target_list_ipv4_access_list_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_bmp_config_target_list_ipv4_access_list_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/ipv6-access-list
 */
int bgp_global_bmp_config_target_list_ipv6_access_list_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_bmp_config_target_list_ipv6_access_list_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi
 */
int bgp_global_bmp_config_target_list_afi_safis_afi_safi_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_bmp_config_target_list_afi_safis_afi_safi_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/mirror-buffer-limit
 */
int bgp_global_bmp_config_mirror_buffer_limit_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_bmp_config_mirror_buffer_limit_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi
 */
int bgp_global_afi_safis_afi_safi_create(struct nb_cb_create_args *args)
{
	const struct lyd_node *vrf_dnode;
	const char *vrf_name;
	const char *af_name;
	afi_t afi;
	safi_t safi;

	switch (args->event) {
	case NB_EV_VALIDATE:
		vrf_dnode = yang_dnode_get_parent(args->dnode,
						  "control-plane-protocol");
		vrf_name = yang_dnode_get_string(vrf_dnode, "./vrf");
		af_name = yang_dnode_get_string(args->dnode, "./afi-safi-name");
		yang_afi_safi_identity2value(af_name, &afi, &safi);

		if ((!strmatch(vrf_name, VRF_DEFAULT_NAME))
		    && safi != SAFI_UNICAST && safi != SAFI_MULTICAST
		    && safi != SAFI_EVPN) {
			snprintf(
				args->errmsg, args->errmsg_len,
				"Only Unicast/Multicast/EVPN SAFIs supported in non-core instances.");
			return NB_ERR_VALIDATION;
		}

		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

static struct peer *bgp_neighbor_peer_lookup(struct bgp *bgp,
					     const char *peer_str, char *errmsg,
					     size_t errmsg_len)
{
	struct peer *peer = NULL;
	union sockunion su;

	str2sockunion(peer_str, &su);
	peer = peer_lookup(bgp, &su);
	if (!peer) {
		snprintf(errmsg, errmsg_len,
			 "Specify remote-as or peer-group commands first");
		return NULL;
	}
	if (peer_dynamic_neighbor(peer)) {
		snprintf(errmsg, errmsg_len,
			 "Operation not allowed on a dynamic neighbor\n");
		return NULL;
	}
	return peer;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor
 */
int bgp_neighbors_neighbor_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	union sockunion su;

	switch (args->event) {
	case NB_EV_VALIDATE:

		peer_str =
			yang_dnode_get_string(args->dnode, "./remote-address");

		bgp = nb_running_get_entry(args->dnode, NULL, false);
		if (!bgp)
			return NB_OK;

		str2sockunion(peer_str, &su);
		if (peer_address_self_check(bgp, &su)) {
			snprintf(
				args->errmsg, args->errmsg_len,
				"Can not configure the local system as neighbor");
			return NB_ERR_VALIDATION;
		}

		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		/* Once bgp instance available check self peer addr */
		bgp = nb_running_get_entry(args->dnode, NULL, true);

		peer_str =
			yang_dnode_get_string(args->dnode, "./remote-address");
		str2sockunion(peer_str, &su);
		if (peer_address_self_check(bgp, &su)) {
			snprintf(
				args->errmsg, args->errmsg_len,
				"Can not configure the local system as neighbor");
			return NB_ERR_INCONSISTENCY;
		}
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_destroy(struct nb_cb_destroy_args *args)
{

	struct bgp *bgp;
	const char *peer_str;
	union sockunion su;
	struct peer *peer = NULL;
	struct peer *other;

	switch (args->event) {
	case NB_EV_VALIDATE:
		bgp = nb_running_get_entry(args->dnode, NULL, false);
		if (!bgp)
			return NB_OK;
		peer_str =
			yang_dnode_get_string(args->dnode, "./remote-address");
		str2sockunion(peer_str, &su);

		peer = peer_lookup(bgp, &su);
		if (peer) {
			if (peer_dynamic_neighbor(peer)) {
				snprintf(
					args->errmsg, args->errmsg_len,
					"Operation not allowed on a dynamic neighbor");
				return NB_ERR_VALIDATION;
			}
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:

		bgp = nb_running_get_entry(args->dnode, NULL, true);

		peer_str =
			yang_dnode_get_string(args->dnode, "./remote-address");
		str2sockunion(peer_str, &su);

		peer = peer_lookup(bgp, &su);
		if (peer) {
			if (peer_dynamic_neighbor(peer)) {
				snprintf(
					args->errmsg, args->errmsg_len,
					"Operation not allowed on a dynamic neighbor");
				return NB_ERR_INCONSISTENCY;
			}

			other = peer->doppelganger;

			if (CHECK_FLAG(peer->flags, PEER_FLAG_CAPABILITY_ENHE))
				bgp_zebra_terminate_radv(peer->bgp, peer);

			peer_notify_unconfig(peer);
			peer_delete(peer);
			if (other && other->status != Deleted) {
				peer_notify_unconfig(other);
				peer_delete(other);
			}
		}

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/local-interface
 */
int bgp_neighbors_neighbor_local_interface_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	const char *intf_str;
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str =
			yang_dnode_get_string(args->dnode, "../remote-address");
		peer = bgp_neighbor_peer_lookup(bgp, peer_str, args->errmsg,
						args->errmsg_len);
		if (!peer) {
			snprintf(args->errmsg, args->errmsg_len,
				 "BGP invalid peer %s", peer_str);
			return NB_ERR_INCONSISTENCY;
		}

		if (peer->conf_if) {
			snprintf(args->errmsg, args->errmsg_len,
				 "BGP invalid peer %s", peer_str);
			return NB_ERR_INCONSISTENCY;
		}

		intf_str = yang_dnode_get_string(args->dnode, NULL);

		peer_interface_set(peer, intf_str);

		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_local_interface_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str =
			yang_dnode_get_string(args->dnode, "../remote-address");
		peer = bgp_neighbor_peer_lookup(bgp, peer_str, args->errmsg,
						args->errmsg_len);
		if (!peer) {
			snprintf(args->errmsg, args->errmsg_len,
				 "BGP invalid peer %s", peer_str);
			return NB_ERR_INCONSISTENCY;
		}

		if (peer->conf_if) {
			snprintf(args->errmsg, args->errmsg_len,
				 "BGP invalid peer %s", peer_str);
			return NB_ERR_INCONSISTENCY;
		}

		peer_interface_unset(peer);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/local-port
 */
int bgp_neighbors_neighbor_local_port_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	uint16_t port;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str =
			yang_dnode_get_string(args->dnode, "../remote-address");
		peer = bgp_neighbor_peer_lookup(bgp, peer_str, args->errmsg,
						args->errmsg_len);
		if (!peer) {
			snprintf(args->errmsg, args->errmsg_len,
				 "BGP invalid peer %s", peer_str);
			return NB_ERR_INCONSISTENCY;
		}

		port = yang_dnode_get_uint16(args->dnode, NULL);
		peer_port_set(peer, port);

		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_local_port_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	uint16_t port;
	struct servent *sp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str =
			yang_dnode_get_string(args->dnode, "../remote-address");
		peer = bgp_neighbor_peer_lookup(bgp, peer_str, args->errmsg,
						args->errmsg_len);
		if (!peer) {
			snprintf(args->errmsg, args->errmsg_len,
				 "BGP invalid peer %s", peer_str);
			return NB_ERR_INCONSISTENCY;
		}

		sp = getservbyname("bgp", "tcp");
		port = (sp == NULL) ? BGP_PORT_DEFAULT : ntohs(sp->s_port);
		peer_port_set(peer, port);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/peer-group
 */
int bgp_neighbors_neighbor_peer_group_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	const char *peer_grp_str;
	struct peer *peer;
	struct peer_group *group;
	union sockunion su;
	as_t as;
	int ret = 0;
	char prgrp_xpath[XPATH_MAXLEN];
	const struct lyd_node *bgp_dnode;

	switch (args->event) {
	case NB_EV_VALIDATE:
		peer_grp_str = yang_dnode_get_string(args->dnode, NULL);
		bgp_dnode = yang_dnode_get_parent(args->dnode, "bgp");
		snprintf(prgrp_xpath, sizeof(prgrp_xpath),
			 FRR_BGP_PEER_GROUP_XPATH, peer_grp_str, "");

		if (!yang_dnode_exists(bgp_dnode, prgrp_xpath)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Configure the peer-group first %s",
				 peer_grp_str);
			return NB_ERR_VALIDATION;
		}

		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str =
			yang_dnode_get_string(args->dnode, "../remote-address");
		peer = bgp_neighbor_peer_lookup(bgp, peer_str, args->errmsg,
						args->errmsg_len);

		str2sockunion(peer_str, &su);

		peer_grp_str = yang_dnode_get_string(args->dnode, NULL);
		group = peer_group_lookup(bgp, peer_grp_str);
		if (!group) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Configure the peer-group first %s",
				 peer_grp_str);
			return NB_ERR_INCONSISTENCY;
		}

		ret = peer_group_bind(bgp, &su, peer, group, &as);

		if (ret == BGP_ERR_PEER_GROUP_PEER_TYPE_DIFFERENT) {
			snprintf(
				args->errmsg, args->errmsg_len,
				"Peer with AS %u cannot be in this peer-group, members must be all internal or all external\n",
				as);
			return NB_ERR_INCONSISTENCY;
		}

		if (bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret)
		    < 0)
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_peer_group_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str =
			yang_dnode_get_string(args->dnode, "../remote-address");
		peer = bgp_neighbor_peer_lookup(bgp, peer_str, args->errmsg,
						args->errmsg_len);

		if (CHECK_FLAG(peer->flags, PEER_FLAG_CAPABILITY_ENHE))
			bgp_zebra_terminate_radv(peer->bgp, peer);

		peer_notify_unconfig(peer);
		ret = peer_delete(peer);

		if (bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret)
		    < 0)
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/password
 */
int bgp_neighbors_neighbor_password_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	const char *passwrd_str;
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str =
			yang_dnode_get_string(args->dnode, "../remote-address");
		peer = bgp_neighbor_peer_lookup(bgp, peer_str, args->errmsg,
						args->errmsg_len);
		if (!peer)
			return NB_ERR_INCONSISTENCY;

		passwrd_str = yang_dnode_get_string(args->dnode, NULL);

		peer_password_set(peer, passwrd_str);

		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_password_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str =
			yang_dnode_get_string(args->dnode, "../remote-address");
		peer = bgp_neighbor_peer_lookup(bgp, peer_str, args->errmsg,
						args->errmsg_len);
		if (!peer)
			return NB_ERR_INCONSISTENCY;

		peer_password_unset(peer);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/ttl-security
 */
int bgp_neighbors_neighbor_ttl_security_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	int ret;
	uint8_t gtsm_hops;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str =
			yang_dnode_get_string(args->dnode, "../remote-address");
		peer = bgp_neighbor_peer_lookup(bgp, peer_str, args->errmsg,
						args->errmsg_len);
		if (!peer)
			return NB_ERR_INCONSISTENCY;

		gtsm_hops = yang_dnode_get_uint8(args->dnode, NULL);
		/*
		 * If 'neighbor swpX', then this is for directly connected
		 * peers, we should not accept a ttl-security hops value greater
		 * than 1.
		 */
		if (peer->conf_if && (gtsm_hops > BGP_GTSM_HOPS_CONNECTED)) {
			snprintf(
				args->errmsg, args->errmsg_len,
				"%d is directly connected peer, hops cannot exceed 1\n",
				gtsm_hops);
			return NB_ERR_INCONSISTENCY;
		}

		ret = peer_ttl_security_hops_set(peer, gtsm_hops);
		if (bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret))
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_ttl_security_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str =
			yang_dnode_get_string(args->dnode, "../remote-address");
		peer = bgp_neighbor_peer_lookup(bgp, peer_str, args->errmsg,
						args->errmsg_len);
		if (!peer)
			return NB_ERR_INCONSISTENCY;

		ret = peer_ttl_security_hops_unset(peer);
		if (bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret)
		    < 0)
			return NB_ERR_INCONSISTENCY;


		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/solo
 */
int bgp_neighbors_neighbor_solo_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/enforce-first-as
 */
int bgp_neighbors_neighbor_enforce_first_as_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	bool enable = false;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str =
			yang_dnode_get_string(args->dnode, "../remote-address");
		peer = bgp_neighbor_peer_lookup(bgp, peer_str, args->errmsg,
						args->errmsg_len);

		enable = yang_dnode_get_bool(args->dnode, NULL);

		peer_flag_modify_nb(bgp, peer_str, peer,
				    PEER_FLAG_ENFORCE_FIRST_AS, enable,
				    args->errmsg, args->errmsg_len);
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/description
 */
int bgp_neighbors_neighbor_description_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	const char *desc_str;
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str =
			yang_dnode_get_string(args->dnode, "../remote-address");

		peer = bgp_neighbor_peer_lookup(bgp, peer_str, args->errmsg,
						args->errmsg_len);
		if (!peer)
			return NB_ERR_INCONSISTENCY;

		desc_str = yang_dnode_get_string(args->dnode, NULL);

		peer_description_set(peer, desc_str);

		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_description_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str =
			yang_dnode_get_string(args->dnode, "../remote-address");
		peer = bgp_neighbor_peer_lookup(bgp, peer_str, args->errmsg,
						args->errmsg_len);
		if (!peer)
			return NB_ERR_INCONSISTENCY;

		peer_description_unset(peer);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/passive-mode
 */
int bgp_neighbors_neighbor_passive_mode_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	bool set = false;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str =
			yang_dnode_get_string(args->dnode, "../remote-address");
		peer = bgp_neighbor_peer_lookup(bgp, peer_str, args->errmsg,
						args->errmsg_len);
		if (!peer)
			return NB_ERR_INCONSISTENCY;

		set = yang_dnode_get_bool(args->dnode, NULL);

		if (peer_flag_modify_nb(bgp, peer_str, peer, PEER_FLAG_PASSIVE,
					set, args->errmsg, args->errmsg_len)
		    < 0)
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/capability-options/dynamic-capability
 */
int bgp_neighbors_neighbor_capability_options_dynamic_capability_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	bool enable = false;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode,
						 "../../remote-address");
		peer = bgp_neighbor_peer_lookup(bgp, peer_str, args->errmsg,
						args->errmsg_len);

		enable = yang_dnode_get_bool(args->dnode, NULL);

		peer_flag_modify_nb(bgp, peer_str, peer,
				    PEER_FLAG_DYNAMIC_CAPABILITY, enable,
				    args->errmsg, args->errmsg_len);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/capability-options/strict-capability
 */
int bgp_neighbors_neighbor_capability_options_strict_capability_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	bool enable = false;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode,
						 "../../remote-address");
		peer = bgp_neighbor_peer_lookup(bgp, peer_str, args->errmsg,
						args->errmsg_len);

		enable = yang_dnode_get_bool(args->dnode, NULL);

		peer_flag_modify_nb(bgp, peer_str, peer,
				    PEER_FLAG_STRICT_CAP_MATCH, enable,
				    args->errmsg, args->errmsg_len);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/capability-options/extended-nexthop-capability
 */
int bgp_neighbors_neighbor_capability_options_extended_nexthop_capability_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	bool enable = false;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode,
						 "../../remote-address");
		peer = bgp_neighbor_peer_lookup(bgp, peer_str, args->errmsg,
						args->errmsg_len);

		enable = yang_dnode_get_bool(args->dnode, NULL);

		peer_flag_modify_nb(bgp, peer_str, peer,
				    PEER_FLAG_CAPABILITY_ENHE, enable,
				    args->errmsg, args->errmsg_len);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/capability-options/capability-negotiate
 */
int bgp_neighbors_neighbor_capability_options_capability_negotiate_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/capability-options/override-capability
 */
int bgp_neighbors_neighbor_capability_options_override_capability_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	bool enable = false;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode,
						 "../../remote-address");
		peer = bgp_neighbor_peer_lookup(bgp, peer_str, args->errmsg,
						args->errmsg_len);

		enable = yang_dnode_get_bool(args->dnode, NULL);

		peer_flag_modify_nb(bgp, peer_str, peer,
				    PEER_FLAG_OVERRIDE_CAPABILITY, enable,
				    args->errmsg, args->errmsg_len);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/update-source/ip
 */
int bgp_neighbors_neighbor_update_source_ip_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str, *source_str;
	struct peer *peer;
	union sockunion su;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode,
						 "../../remote-address");
		peer = bgp_neighbor_peer_lookup(bgp, peer_str, args->errmsg,
						args->errmsg_len);
		if (!peer)
			return NB_ERR_INCONSISTENCY;

		source_str = yang_dnode_get_string(args->dnode, NULL);

		str2sockunion(source_str, &su);
		peer_update_source_addr_set(peer, &su);

		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_update_source_ip_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode,
						 "../../remote-address");
		peer = bgp_neighbor_peer_lookup(bgp, peer_str, args->errmsg,
						args->errmsg_len);
		if (!peer)
			return NB_ERR_INCONSISTENCY;

		peer_update_source_unset(peer);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/update-source/interface
 */
int bgp_neighbors_neighbor_update_source_interface_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str, *source_str;
	struct peer *peer;
	struct prefix p;

	switch (args->event) {
	case NB_EV_VALIDATE:
		source_str = yang_dnode_get_string(args->dnode, NULL);
		if (str2prefix(source_str, &p)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Invalid update-source, remove prefix length");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode,
						 "../../remote-address");
		peer = bgp_neighbor_peer_lookup(bgp, peer_str, args->errmsg,
						args->errmsg_len);
		if (!peer)
			return NB_ERR_INCONSISTENCY;

		source_str = yang_dnode_get_string(args->dnode, NULL);

		peer_update_source_if_set(peer, source_str);

		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_update_source_interface_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode,
						 "../../remote-address");
		peer = bgp_neighbor_peer_lookup(bgp, peer_str, args->errmsg,
						args->errmsg_len);
		if (!peer)
			return NB_ERR_INCONSISTENCY;

		peer_update_source_unset(peer);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/neighbor-remote-as/remote-as-type
 */
int bgp_neighbors_neighbor_neighbor_remote_as_remote_as_type_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	int as_type = AS_SPECIFIED;
	union sockunion su;
	int ret;
	as_t as = 0;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);

		peer_str = yang_dnode_get_string(args->dnode,
						 "../../remote-address");
		as_type = yang_dnode_get_enum(args->dnode, "../remote-as-type");
		/* When remote-as-type is as-specified, the peer will be
		 * created in remote_as_modify callback */
		if (yang_dnode_exists(args->dnode, "../remote-as"))
			return NB_OK;

		str2sockunion(peer_str, &su);
		ret = peer_remote_as(bgp, &su, NULL, &as, as_type, AFI_IP,
				     SAFI_UNICAST);
		if (bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret)
		    < 0)
			return NB_ERR_INCONSISTENCY;


		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_neighbor_remote_as_remote_as_type_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/neighbor-remote-as/remote-as
 */
int bgp_neighbors_neighbor_neighbor_remote_as_remote_as_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	int as_type = AS_SPECIFIED;
	union sockunion su;
	int ret;
	as_t as = 0;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);

		peer_str = yang_dnode_get_string(args->dnode,
						 "../../remote-address");
		as_type = yang_dnode_get_enum(args->dnode, "../remote-as-type");
		as = yang_dnode_get_uint32(args->dnode, NULL);

		str2sockunion(peer_str, &su);
		ret = peer_remote_as(bgp, &su, NULL, &as, as_type, AFI_IP,
				     SAFI_UNICAST);
		if (bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret)
		    < 0)
			return NB_ERR_INCONSISTENCY;


		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_neighbor_remote_as_remote_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/ebgp-multihop/enabled
 */
int bgp_neighbors_neighbor_ebgp_multihop_enabled_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	bool set = false;
	int ret = 0;
	uint8_t ttl = MAXTTL;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode,
						 "../../remote-address");
		peer = bgp_neighbor_peer_lookup(bgp, peer_str, args->errmsg,
						args->errmsg_len);
		if (!peer)
			return NB_ERR_INCONSISTENCY;

		if (peer->conf_if) {
			ret = BGP_ERR_INVALID_FOR_DIRECT_PEER;
			bgp_nb_errmsg_return(args->errmsg, args->errmsg_len,
					     ret);
			return NB_ERR_INCONSISTENCY;
		}

		set = yang_dnode_get_bool(args->dnode, NULL);

		if (set)
			ret = peer_ebgp_multihop_set(peer, ttl);
		else
			ret = peer_ebgp_multihop_unset(peer);

		if (bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret)
		    < 0)
			return NB_ERR_INCONSISTENCY;


		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_ebgp_multihop_enabled_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	int ret = 0;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode,
						 "../../remote-address");
		peer = bgp_neighbor_peer_lookup(bgp, peer_str, args->errmsg,
						args->errmsg_len);
		if (!peer)
			return NB_ERR_INCONSISTENCY;

		ret = peer_ebgp_multihop_unset(peer);

		if (bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret)
		    < 0)
			return NB_ERR_INCONSISTENCY;


		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/ebgp-multihop/multihop-ttl
 */
int bgp_neighbors_neighbor_ebgp_multihop_multihop_ttl_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	int ret = 0;
	uint8_t ttl = MAXTTL;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode,
						 "../../remote-address");
		peer = bgp_neighbor_peer_lookup(bgp, peer_str, args->errmsg,
						args->errmsg_len);
		if (!peer)
			return NB_ERR_INCONSISTENCY;

		if (peer->conf_if) {
			ret = BGP_ERR_INVALID_FOR_DIRECT_PEER;
			bgp_nb_errmsg_return(args->errmsg, args->errmsg_len,
					     ret);
			return NB_ERR_INCONSISTENCY;
		}

		ttl = yang_dnode_get_uint8(args->dnode, NULL);

		ret = peer_ebgp_multihop_set(peer, ttl);

		bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret);

		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_ebgp_multihop_multihop_ttl_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	int ret = 0;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode,
						 "../../remote-address");
		peer = bgp_neighbor_peer_lookup(bgp, peer_str, args->errmsg,
						args->errmsg_len);
		if (!peer)
			return NB_ERR_INCONSISTENCY;

		ret = peer_ebgp_multihop_unset(peer);

		bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/ebgp-multihop/disable-connected-check
 */
int bgp_neighbors_neighbor_ebgp_multihop_disable_connected_check_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	bool set = false;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode,
						 "../../remote-address");
		peer = bgp_neighbor_peer_lookup(bgp, peer_str, args->errmsg,
						args->errmsg_len);
		if (!peer)
			return NB_ERR_INCONSISTENCY;

		set = yang_dnode_get_bool(args->dnode, NULL);

		if (peer_flag_modify_nb(bgp, peer_str, peer,
					PEER_FLAG_DISABLE_CONNECTED_CHECK, set,
					args->errmsg, args->errmsg_len)
		    < 0)
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/local-as
 */
void bgp_neighbors_neighbor_local_as_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	struct bgp *bgp;
	int ret;
	as_t as = 0;
	const char *peer_str;
	struct peer *peer = NULL;
	bool no_prepend = 0;
	bool replace_as = 0;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	peer_str = yang_dnode_get_string(args->dnode, "../remote-address");
	peer = bgp_neighbor_peer_lookup(bgp, peer_str, args->errmsg,
					args->errmsg_len);

	if (yang_dnode_exists(args->dnode, "./local-as"))
		as = yang_dnode_get_uint32(args->dnode, "./local-as");
	if (yang_dnode_exists(args->dnode, "./no-prepend"))
		no_prepend = yang_dnode_get_bool(args->dnode, "./no-prepend");
	if (yang_dnode_exists(args->dnode, "./no-replace-as"))
		replace_as =
			yang_dnode_get_bool(args->dnode, "./no-replace-as");

	if (!as && !no_prepend && !replace_as)
		ret = peer_local_as_unset(peer);
	else
		ret = peer_local_as_set(peer, as, no_prepend, replace_as);
	bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret);
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/local-as/local-as
 */
int bgp_neighbors_neighbor_local_as_local_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_local_as_local_as_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	int ret;
	const char *peer_str;
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode,
						 "../../remote-address");


		peer = bgp_neighbor_peer_lookup(bgp, peer_str, args->errmsg,
						args->errmsg_len);

		ret = peer_local_as_unset(peer);
		if (bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret)
		    < 0)
			return NB_ERR_INCONSISTENCY;


		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/local-as/no-prepend
 */
int bgp_neighbors_neighbor_local_as_no_prepend_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_local_as_no_prepend_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/local-as/no-replace-as
 */
int bgp_neighbors_neighbor_local_as_no_replace_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/bfd-options/enable
 */
int bgp_neighbors_neighbor_bfd_options_enable_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/bfd-options/detect-multiplier
 */
int bgp_neighbors_neighbor_bfd_options_detect_multiplier_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_bfd_options_detect_multiplier_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/bfd-options/required-min-rx
 */
int bgp_neighbors_neighbor_bfd_options_required_min_rx_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_bfd_options_required_min_rx_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/bfd-options/desired-min-tx
 */
int bgp_neighbors_neighbor_bfd_options_desired_min_tx_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_bfd_options_desired_min_tx_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/bfd-options/session-type
 */
int bgp_neighbors_neighbor_bfd_options_session_type_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_bfd_options_session_type_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/bfd-options/check-cp-failure
 */
int bgp_neighbors_neighbor_bfd_options_check_cp_failure_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_bfd_options_check_cp_failure_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/admin-shutdown
 */
void bgp_neighbors_neighbor_admin_shutdown_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	bool enable = false;
	const char *message;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	peer_str = yang_dnode_get_string(args->dnode, "../remote-address");
	peer = bgp_neighbor_peer_lookup(bgp, peer_str, args->errmsg,
					args->errmsg_len);

	if (yang_dnode_exists(args->dnode, "./message")) {
		message = yang_dnode_get_string(args->dnode, "./message");
		peer_tx_shutdown_message_set(peer, message);
	}
	enable = yang_dnode_get_bool(args->dnode, "./enable");

	peer_flag_modify_nb(bgp, peer_str, peer, PEER_FLAG_SHUTDOWN, enable,
			    args->errmsg, args->errmsg_len);
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/admin-shutdown/enable
 */
int bgp_neighbors_neighbor_admin_shutdown_enable_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_admin_shutdown_enable_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/admin-shutdown/message
 */
int bgp_neighbors_neighbor_admin_shutdown_message_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_admin_shutdown_message_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/graceful-restart/enable
 */
int bgp_neighbors_neighbor_graceful_restart_enable_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_graceful_restart_enable_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/graceful-restart/graceful-restart-helper
 */
int bgp_neighbors_neighbor_graceful_restart_graceful_restart_helper_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_graceful_restart_graceful_restart_helper_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/graceful-restart/graceful-restart-disable
 */
int bgp_neighbors_neighbor_graceful_restart_graceful_restart_disable_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_graceful_restart_graceful_restart_disable_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/timers/advertise-interval
 */
int bgp_neighbors_neighbor_timers_advertise_interval_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	uint16_t routeadv;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode,
						 "../../remote-address");
		peer = bgp_neighbor_peer_lookup(bgp, peer_str, args->errmsg,
						args->errmsg_len);
		routeadv = yang_dnode_get_uint16(args->dnode, NULL);

		ret = peer_advertise_interval_set(peer, routeadv);
		if (bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret)
		    < 0)
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_timers_advertise_interval_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode,
						 "../../remote-address");
		peer = bgp_neighbor_peer_lookup(bgp, peer_str, args->errmsg,
						args->errmsg_len);

		ret = peer_advertise_interval_unset(peer);
		if (bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret)
		    < 0)
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/timers/connect-time
 */
int bgp_neighbors_neighbor_timers_connect_time_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	uint16_t connect;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode,
						 "../../remote-address");
		peer = bgp_neighbor_peer_lookup(bgp, peer_str, args->errmsg,
						args->errmsg_len);
		connect = yang_dnode_get_uint16(args->dnode, NULL);

		ret = peer_timers_connect_set(peer, connect);
		if (bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret)
		    < 0)
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_timers_connect_time_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode,
						 "../../remote-address");
		peer = bgp_neighbor_peer_lookup(bgp, peer_str, args->errmsg,
						args->errmsg_len);

		ret = peer_timers_connect_unset(peer);
		if (bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret)
		    < 0)
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/timers/hold-time
 */
int bgp_neighbors_neighbor_timers_hold_time_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	uint16_t keepalive = 0;
	uint16_t holdtime = 0;
	int ret = 0;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode,
						 "../../remote-address");
		peer = bgp_neighbor_peer_lookup(bgp, peer_str, args->errmsg,
						args->errmsg_len);
		keepalive = yang_dnode_get_uint16(args->dnode, "../keepalive");
		holdtime = yang_dnode_get_uint16(args->dnode, NULL);

		if (keepalive != BGP_DEFAULT_KEEPALIVE
		    && holdtime != BGP_DEFAULT_HOLDTIME) {
			ret = peer_timers_set(peer, keepalive, holdtime);
		} else
			ret = peer_timers_unset(peer);

		if (bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret)
		    < 0)
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/timers/keepalive
 */
int bgp_neighbors_neighbor_timers_keepalive_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	uint16_t keepalive = 0, curr_keep = 0;
	uint16_t holdtime = 0;
	int ret = 0;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode,
						 "../../remote-address");
		peer = bgp_neighbor_peer_lookup(bgp, peer_str, args->errmsg,
						args->errmsg_len);
		keepalive = yang_dnode_get_uint16(args->dnode, NULL);
		holdtime = yang_dnode_get_uint16(args->dnode, "../hold-time");

		if (keepalive != BGP_DEFAULT_KEEPALIVE
		    && holdtime != BGP_DEFAULT_HOLDTIME) {
			if (peer->holdtime == holdtime) {
				curr_keep = (keepalive < holdtime / 3
						     ? keepalive
						     : holdtime / 3);
				if (curr_keep == keepalive)
					return NB_OK;
			}
			ret = peer_timers_set(peer, keepalive, holdtime);
		} else
			ret = peer_timers_unset(peer);

		if (bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret)
		    < 0)
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/enabled
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_enabled_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	const char *af_name;
	afi_t afi;
	safi_t safi;
	bool activate = false;
	int ret = 0;
	union sockunion su;
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		af_name =
			yang_dnode_get_string(args->dnode, "../afi-safi-name");
		yang_afi_safi_identity2value(af_name, &afi, &safi);
		peer_str = yang_dnode_get_string(args->dnode,
						 "../../../remote-address");
		str2sockunion(peer_str, &su);
		peer = peer_lookup(bgp, &su);

		activate = yang_dnode_get_bool(args->dnode, NULL);

		if (activate)
			ret = peer_activate(peer, afi, safi);
		else
			ret = peer_deactivate(peer, afi, safi);

		bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret);

		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_enabled_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

static struct peer *bgp_unnumbered_neighbor_peer_lookup(struct bgp *bgp,
							const char *peer_str,
							char *errmsg,
							size_t errmsg_len)
{
	struct peer *peer = NULL;

	/* Not IP, could match either peer configured on interface or a
	 * group. */
	peer = peer_lookup_by_conf_if(bgp, peer_str);
	if (!peer) {
		snprintf(errmsg, errmsg_len,
			 "Specify remote-as or peer-group commands first");
		return NULL;
	}
	if (peer_dynamic_neighbor(peer)) {
		snprintf(errmsg, errmsg_len,
			 "Operation not allowed on a dynamic neighbor\n");
		return NULL;
	}

	return peer;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor
 */
int bgp_neighbors_unnumbered_neighbor_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	const char *peer_grp_str = NULL;
	bool v6_only = false;
	int as_type = AS_UNSPECIFIED;
	as_t as = 0;
	char prgrp_xpath[XPATH_MAXLEN];
	const struct lyd_node *bgp_dnode;

	switch (args->event) {
	case NB_EV_VALIDATE:
		peer_str = yang_dnode_get_string(args->dnode, "./interface");
		bgp_dnode = yang_dnode_get_parent(args->dnode, "bgp");
		snprintf(prgrp_xpath, sizeof(prgrp_xpath),
			 FRR_BGP_PEER_GROUP_XPATH, peer_str, "");

		if (yang_dnode_exists(bgp_dnode, prgrp_xpath)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Name conflict with peer-group: %s", peer_str);
			return NB_ERR_VALIDATION;
		}

		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode, "./interface");

		if (yang_dnode_exists(args->dnode, "./peer-group"))
			peer_grp_str = yang_dnode_get_string(args->dnode,
							     "./peer-group");

		if (yang_dnode_exists(args->dnode, "./v6-only"))
			v6_only = yang_dnode_get_bool(args->dnode, "./v6-only");

		if (yang_dnode_exists(args->dnode,
				      "./neighbor-remote-as/remote-as-type")) {
			as_type = yang_dnode_get_enum(
				args->dnode,
				"./neighbor-remote-as/remote-as-type");
			if (yang_dnode_exists(args->dnode,
					      "./neighbor-remote-as/remote-as"))
				as = yang_dnode_get_uint32(
					args->dnode,
					"./neighbor-remote-as/remote-as");
		}

		if (peer_conf_interface_create(bgp, peer_str, AFI_IP,
					       SAFI_UNICAST, v6_only,
					       peer_grp_str, as_type, as,
					       args->errmsg, args->errmsg_len))
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);

		peer_str = yang_dnode_get_string(args->dnode, "./interface");
		/* look up for neighbor by interface name config. */
		peer = peer_lookup_by_conf_if(bgp, peer_str);
		if (peer) {
			/* Request zebra to terminate IPv6 RAs on this
			 * interface. */
			if (peer->ifp)
				bgp_zebra_terminate_radv(peer->bgp, peer);
			peer_notify_unconfig(peer);
			peer_delete(peer);
		} else {
			snprintf(args->errmsg, args->errmsg_len,
				 "Create the peer-group first");
			return NB_ERR_INCONSISTENCY;
		}

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/v6only
 */
int bgp_neighbors_unnumbered_neighbor_v6only_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	bool v6_only = false;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode, "../interface");

		v6_only = yang_dnode_get_bool(args->dnode, NULL);

		if (peer_conf_interface_create(
			    bgp, peer_str, AFI_IP, SAFI_UNICAST, v6_only, NULL,
			    AS_UNSPECIFIED, 0, args->errmsg, args->errmsg_len))
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/peer-group
 */
int bgp_neighbors_unnumbered_neighbor_peer_group_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	const char *peer_grp_str;
	struct peer *peer;
	struct peer_group *group;
	union sockunion su;
	as_t as;
	int ret = 0;
	char prgrp_xpath[XPATH_MAXLEN];
	const struct lyd_node *bgp_dnode;

	switch (args->event) {
	case NB_EV_VALIDATE:
		peer_grp_str = yang_dnode_get_string(args->dnode, NULL);
		bgp_dnode = yang_dnode_get_parent(args->dnode, "bgp");
		snprintf(prgrp_xpath, sizeof(prgrp_xpath),
			 FRR_BGP_PEER_GROUP_XPATH, peer_grp_str, "");

		if (!yang_dnode_exists(bgp_dnode, prgrp_xpath)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Configure the peer-group first %s",
				 peer_grp_str);
			return NB_ERR_VALIDATION;
		}

		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode, "../interface");
		peer = bgp_unnumbered_neighbor_peer_lookup(
			bgp, peer_str, args->errmsg, args->errmsg_len);

		peer_grp_str = yang_dnode_get_string(args->dnode, NULL);
		group = peer_group_lookup(bgp, peer_grp_str);
		if (!group) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Configure the peer-group first\n");
			return NB_ERR_INCONSISTENCY;
		}

		ret = peer_group_bind(bgp, &su, peer, group, &as);
		if (ret == BGP_ERR_PEER_GROUP_PEER_TYPE_DIFFERENT) {
			snprintf(
				args->errmsg, args->errmsg_len,
				"Peer with AS %u cannot be in this peer-group, members must be all internal or all external\n",
				as);
			return NB_ERR_INCONSISTENCY;
		}

		bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret);

		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_peer_group_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str =
			yang_dnode_get_string(args->dnode, "../remote-address");
		peer = bgp_unnumbered_neighbor_peer_lookup(
			bgp, peer_str, args->errmsg, args->errmsg_len);

		if (CHECK_FLAG(peer->flags, PEER_FLAG_CAPABILITY_ENHE))
			bgp_zebra_terminate_radv(peer->bgp, peer);

		peer_notify_unconfig(peer);
		ret = peer_delete(peer);

		if (bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret)
		    < 0)
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/password
 */
int bgp_neighbors_unnumbered_neighbor_password_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	const char *passwrd_str;
	struct peer *peer = NULL;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode, "../interface");
		peer = bgp_unnumbered_neighbor_peer_lookup(
			bgp, peer_str, args->errmsg, args->errmsg_len);
		if (!peer)
			return NB_ERR_INCONSISTENCY;

		passwrd_str = yang_dnode_get_string(args->dnode, NULL);
		peer_password_set(peer, passwrd_str);

		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_password_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer = NULL;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode, "../interface");
		peer = bgp_unnumbered_neighbor_peer_lookup(
			bgp, peer_str, args->errmsg, args->errmsg_len);
		if (!peer)
			return NB_ERR_INCONSISTENCY;

		peer_password_unset(peer);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/ttl-security
 */
int bgp_neighbors_unnumbered_neighbor_ttl_security_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	int ret;
	uint8_t gtsm_hops;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode, "../interface");
		peer = bgp_unnumbered_neighbor_peer_lookup(
			bgp, peer_str, args->errmsg, args->errmsg_len);
		if (!peer)
			return NB_ERR_INCONSISTENCY;

		gtsm_hops = yang_dnode_get_uint8(args->dnode, NULL);
		/*
		 * If 'neighbor swpX', then this is for directly connected
		 * peers, we should not accept a ttl-security hops value greater
		 * than 1.
		 */
		if (peer->conf_if && (gtsm_hops > BGP_GTSM_HOPS_CONNECTED)) {
			snprintf(
				args->errmsg, args->errmsg_len,
				"%d is directly connected peer, hops cannot exceed 1\n",
				gtsm_hops);
			return NB_ERR_INCONSISTENCY;
		}

		ret = peer_ttl_security_hops_set(peer, gtsm_hops);
		if (bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret)
		    < 0)
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_ttl_security_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode, "../interface");
		peer = bgp_unnumbered_neighbor_peer_lookup(
			bgp, peer_str, args->errmsg, args->errmsg_len);
		if (!peer)
			return NB_ERR_INCONSISTENCY;

		ret = peer_ttl_security_hops_unset(peer);
		bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/solo
 */
int bgp_neighbors_unnumbered_neighbor_solo_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/enforce-first-as
 */
int bgp_neighbors_unnumbered_neighbor_enforce_first_as_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	bool enable = false;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode, "../interface");
		peer = bgp_unnumbered_neighbor_peer_lookup(
			bgp, peer_str, args->errmsg, args->errmsg_len);

		enable = yang_dnode_get_bool(args->dnode, NULL);

		peer_flag_modify_nb(bgp, peer_str, peer,
				    PEER_FLAG_ENFORCE_FIRST_AS, enable,
				    args->errmsg, args->errmsg_len);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/description
 */
int bgp_neighbors_unnumbered_neighbor_description_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	const char *desc_str;
	struct peer *peer = NULL;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode, "../interface");

		peer = bgp_unnumbered_neighbor_peer_lookup(
			bgp, peer_str, args->errmsg, args->errmsg_len);
		if (!peer)
			return NB_ERR_INCONSISTENCY;

		desc_str = yang_dnode_get_string(args->dnode, NULL);

		peer_description_set(peer, desc_str);

		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_description_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer = NULL;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode, "../interface");

		peer = bgp_unnumbered_neighbor_peer_lookup(
			bgp, peer_str, args->errmsg, args->errmsg_len);
		if (!peer)
			return NB_ERR_INCONSISTENCY;

		peer_description_unset(peer);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/passive-mode
 */
int bgp_neighbors_unnumbered_neighbor_passive_mode_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	bool set = false;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode, "../interface");
		peer = bgp_unnumbered_neighbor_peer_lookup(
			bgp, peer_str, args->errmsg, args->errmsg_len);
		if (!peer)
			return NB_ERR_INCONSISTENCY;

		set = yang_dnode_get_bool(args->dnode, NULL);

		if (peer_flag_modify_nb(bgp, peer_str, peer, PEER_FLAG_PASSIVE,
					set, args->errmsg, args->errmsg_len)
		    < 0)
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/capability-options/dynamic-capability
 */
int bgp_neighbors_unnumbered_neighbor_capability_options_dynamic_capability_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	bool enable = false;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str =
			yang_dnode_get_string(args->dnode, "../../interface");
		peer = bgp_unnumbered_neighbor_peer_lookup(
			bgp, peer_str, args->errmsg, args->errmsg_len);
		if (!peer)
			return NB_ERR_INCONSISTENCY;

		enable = yang_dnode_get_bool(args->dnode, NULL);

		peer_flag_modify_nb(bgp, peer_str, peer,
				    PEER_FLAG_DYNAMIC_CAPABILITY, enable,
				    args->errmsg, args->errmsg_len);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/capability-options/strict-capability
 */
int bgp_neighbors_unnumbered_neighbor_capability_options_strict_capability_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	bool enable = false;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str =
			yang_dnode_get_string(args->dnode, "../../interface");
		peer = bgp_unnumbered_neighbor_peer_lookup(
			bgp, peer_str, args->errmsg, args->errmsg_len);
		if (!peer)
			return NB_ERR_INCONSISTENCY;

		enable = yang_dnode_get_bool(args->dnode, NULL);

		peer_flag_modify_nb(bgp, peer_str, peer,
				    PEER_FLAG_STRICT_CAP_MATCH, enable,
				    args->errmsg, args->errmsg_len);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/capability-options/extended-nexthop-capability
 */
int bgp_neighbors_unnumbered_neighbor_capability_options_extended_nexthop_capability_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	bool enable = false;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str =
			yang_dnode_get_string(args->dnode, "../../interface");
		peer = bgp_unnumbered_neighbor_peer_lookup(
			bgp, peer_str, args->errmsg, args->errmsg_len);
		if (!peer)
			return NB_ERR_INCONSISTENCY;

		enable = yang_dnode_get_bool(args->dnode, NULL);

		peer_flag_modify_nb(bgp, peer_str, peer,
				    PEER_FLAG_CAPABILITY_ENHE, enable,
				    args->errmsg, args->errmsg_len);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/capability-options/capability-negotiate
 */
int bgp_neighbors_unnumbered_neighbor_capability_options_capability_negotiate_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/capability-options/override-capability
 */
int bgp_neighbors_unnumbered_neighbor_capability_options_override_capability_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	bool enable = false;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str =
			yang_dnode_get_string(args->dnode, "../../interface");
		peer = bgp_unnumbered_neighbor_peer_lookup(
			bgp, peer_str, args->errmsg, args->errmsg_len);

		enable = yang_dnode_get_bool(args->dnode, NULL);

		peer_flag_modify_nb(bgp, peer_str, peer,
				    PEER_FLAG_OVERRIDE_CAPABILITY, enable,
				    args->errmsg, args->errmsg_len);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/update-source/ip
 */
int bgp_neighbors_unnumbered_neighbor_update_source_ip_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str, *source_str;
	struct peer *peer;
	union sockunion su;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str =
			yang_dnode_get_string(args->dnode, "../../interface");
		peer = bgp_unnumbered_neighbor_peer_lookup(
			bgp, peer_str, args->errmsg, args->errmsg_len);
		if (!peer)
			return NB_ERR_INCONSISTENCY;

		source_str = yang_dnode_get_string(args->dnode, NULL);

		str2sockunion(source_str, &su);
		peer_update_source_addr_set(peer, &su);

		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_update_source_ip_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str =
			yang_dnode_get_string(args->dnode, "../../interface");
		peer = bgp_unnumbered_neighbor_peer_lookup(
			bgp, peer_str, args->errmsg, args->errmsg_len);
		if (!peer)
			return NB_ERR_INCONSISTENCY;

		peer_update_source_unset(peer);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/update-source/interface
 */
int bgp_neighbors_unnumbered_neighbor_update_source_interface_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str, *source_str;
	struct peer *peer;
	struct prefix p;

	switch (args->event) {
	case NB_EV_VALIDATE:
		source_str = yang_dnode_get_string(args->dnode, NULL);
		if (str2prefix(source_str, &p)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Invalid update-source, remove prefix length");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str =
			yang_dnode_get_string(args->dnode, "../../interface");
		peer = bgp_unnumbered_neighbor_peer_lookup(
			bgp, peer_str, args->errmsg, args->errmsg_len);
		if (!peer)
			return NB_ERR_INCONSISTENCY;

		source_str = yang_dnode_get_string(args->dnode, NULL);

		peer_update_source_if_set(peer, source_str);

		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_update_source_interface_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str =
			yang_dnode_get_string(args->dnode, "../../interface");
		peer = bgp_unnumbered_neighbor_peer_lookup(
			bgp, peer_str, args->errmsg, args->errmsg_len);
		if (!peer)
			return NB_ERR_INCONSISTENCY;

		peer_update_source_unset(peer);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/neighbor-remote-as
 */
void bgp_neighbors_unnumbered_neighbor_neighbor_remote_as_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	int as_type = AS_SPECIFIED;
	int ret;
	as_t as = 0;
	struct peer *peer = NULL;
	afi_t afi = AFI_IP;
	safi_t safi = SAFI_UNICAST;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	peer_str = yang_dnode_get_string(args->dnode, "../interface");
	as_type = yang_dnode_get_enum(args->dnode, "./remote-as-type");
	if (yang_dnode_exists(args->dnode, "./remote-as"))
		as = yang_dnode_get_uint32(args->dnode, "./remote-as");

	peer = peer_lookup_by_conf_if(bgp, peer_str);

	ret = peer_remote_as(bgp, NULL, peer_str, &as, as_type, afi, safi);

	if (ret < 0 && !peer) {
		snprintf(args->errmsg, args->errmsg_len,
			 "Create the peer-group or interface first");
		return;
	}

	bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret);
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/neighbor-remote-as/remote-as-type
 */
int bgp_neighbors_unnumbered_neighbor_neighbor_remote_as_remote_as_type_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_neighbor_remote_as_remote_as_type_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str =
			yang_dnode_get_string(args->dnode, "../../interface");
		peer = peer_lookup_by_conf_if(bgp, peer_str);

		/* remote-as set to 0 and as_type to unspecified */
		if (peer)
			peer_as_change(peer, 0, AS_UNSPECIFIED);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/neighbor-remote-as/remote-as
 */
int bgp_neighbors_unnumbered_neighbor_neighbor_remote_as_remote_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_neighbor_remote_as_remote_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/ebgp-multihop/enabled
 */
int bgp_neighbors_unnumbered_neighbor_ebgp_multihop_enabled_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	bool set = false;
	int ret = 0;
	uint8_t ttl = MAXTTL;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str =
			yang_dnode_get_string(args->dnode, "../../interface");
		peer = peer_lookup_by_conf_if(bgp, peer_str);
		if (!peer)
			return NB_ERR_INCONSISTENCY;

		if (peer->conf_if) {
			ret = BGP_ERR_INVALID_FOR_DIRECT_PEER;
			bgp_nb_errmsg_return(args->errmsg, args->errmsg_len,
					     ret);
			return NB_ERR_INCONSISTENCY;
		}

		set = yang_dnode_get_bool(args->dnode, NULL);

		if (set)
			ret = peer_ebgp_multihop_set(peer, ttl);
		else
			ret = peer_ebgp_multihop_unset(peer);

		bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret);

		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_ebgp_multihop_enabled_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	int ret = 0;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str =
			yang_dnode_get_string(args->dnode, "../../interface");
		peer = peer_lookup_by_conf_if(bgp, peer_str);
		if (!peer)
			return NB_ERR_INCONSISTENCY;

		ret = peer_ebgp_multihop_unset(peer);

		bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/ebgp-multihop/multihop-ttl
 */
int bgp_neighbors_unnumbered_neighbor_ebgp_multihop_multihop_ttl_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	int ret = 0;
	uint8_t ttl = MAXTTL;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str =
			yang_dnode_get_string(args->dnode, "../../interface");
		peer = peer_lookup_by_conf_if(bgp, peer_str);
		if (!peer)
			return NB_ERR_INCONSISTENCY;

		if (peer->conf_if) {
			ret = BGP_ERR_INVALID_FOR_DIRECT_PEER;
			bgp_nb_errmsg_return(args->errmsg, args->errmsg_len,
					     ret);
			return NB_ERR_INCONSISTENCY;
		}

		ttl = yang_dnode_get_uint8(args->dnode, NULL);

		ret = peer_ebgp_multihop_set(peer, ttl);

		bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret);

		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_ebgp_multihop_multihop_ttl_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	int ret = 0;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str =
			yang_dnode_get_string(args->dnode, "../../interface");
		peer = peer_lookup_by_conf_if(bgp, peer_str);
		if (!peer)
			return NB_ERR_INCONSISTENCY;

		ret = peer_ebgp_multihop_unset(peer);

		bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/ebgp-multihop/disable-connected-check
 */
int bgp_neighbors_unnumbered_neighbor_ebgp_multihop_disable_connected_check_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	bool set = false;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str =
			yang_dnode_get_string(args->dnode, "../../interface");
		peer = peer_lookup_by_conf_if(bgp, peer_str);
		if (!peer)
			return NB_ERR_INCONSISTENCY;

		set = yang_dnode_get_bool(args->dnode, NULL);

		if (peer_flag_modify_nb(bgp, peer_str, peer,
					PEER_FLAG_DISABLE_CONNECTED_CHECK, set,
					args->errmsg, args->errmsg_len)
		    < 0)
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/local-as
 */
void bgp_neighbors_unnumbered_neighbor_local_as_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	struct bgp *bgp;
	int ret;
	as_t as = 0;
	const char *peer_str;
	struct peer *peer = NULL;
	bool no_prepend = 0;
	bool replace_as = 0;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	peer_str = yang_dnode_get_string(args->dnode, "../interface");

	peer = bgp_unnumbered_neighbor_peer_lookup(bgp, peer_str, args->errmsg,
						   args->errmsg_len);

	if (yang_dnode_exists(args->dnode, "./local-as"))
		as = yang_dnode_get_uint32(args->dnode, "./local-as");
	if (yang_dnode_exists(args->dnode, "./no-prepend"))
		no_prepend = yang_dnode_get_bool(args->dnode, "./no-prepend");
	if (yang_dnode_exists(args->dnode, "./no-replace-as"))
		replace_as =
			yang_dnode_get_bool(args->dnode, "./no-replace-as");

	if (!as && !no_prepend && !replace_as)
		ret = peer_local_as_unset(peer);
	else
		ret = peer_local_as_set(peer, as, no_prepend, replace_as);

	bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret);
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/local-as/local-as
 */
int bgp_neighbors_unnumbered_neighbor_local_as_local_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_local_as_local_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/local-as/no-prepend
 */
int bgp_neighbors_unnumbered_neighbor_local_as_no_prepend_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_local_as_no_prepend_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/local-as/no-replace-as
 */
int bgp_neighbors_unnumbered_neighbor_local_as_no_replace_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/bfd-options/enable
 */
int bgp_neighbors_unnumbered_neighbor_bfd_options_enable_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/bfd-options/detect-multiplier
 */
int bgp_neighbors_unnumbered_neighbor_bfd_options_detect_multiplier_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_bfd_options_detect_multiplier_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/bfd-options/required-min-rx
 */
int bgp_neighbors_unnumbered_neighbor_bfd_options_required_min_rx_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_bfd_options_required_min_rx_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/bfd-options/desired-min-tx
 */
int bgp_neighbors_unnumbered_neighbor_bfd_options_desired_min_tx_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_bfd_options_desired_min_tx_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/bfd-options/session-type
 */
int bgp_neighbors_unnumbered_neighbor_bfd_options_session_type_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_bfd_options_session_type_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/bfd-options/check-cp-failure
 */
int bgp_neighbors_unnumbered_neighbor_bfd_options_check_cp_failure_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_bfd_options_check_cp_failure_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/admin-shutdown
 */
void bgp_neighbors_unnumbered_neighbor_admin_shutdown_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	bool enable = false;
	const char *message;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	peer_str = yang_dnode_get_string(args->dnode, "../interface");
	peer = bgp_unnumbered_neighbor_peer_lookup(bgp, peer_str, args->errmsg,
						   args->errmsg_len);

	if (yang_dnode_exists(args->dnode, "./message")) {
		message = yang_dnode_get_string(args->dnode, "./message");
		peer_tx_shutdown_message_set(peer, message);
	}
	enable = yang_dnode_get_bool(args->dnode, "./enable");

	peer_flag_modify_nb(bgp, peer_str, peer, PEER_FLAG_SHUTDOWN, enable,
			    args->errmsg, args->errmsg_len);
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/admin-shutdown/enable
 */
int bgp_neighbors_unnumbered_neighbor_admin_shutdown_enable_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_admin_shutdown_enable_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/admin-shutdown/message
 */
int bgp_neighbors_unnumbered_neighbor_admin_shutdown_message_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_admin_shutdown_message_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/graceful-restart/enable
 */
int bgp_neighbors_unnumbered_neighbor_graceful_restart_enable_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_graceful_restart_enable_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/graceful-restart/graceful-restart-helper
 */
int bgp_neighbors_unnumbered_neighbor_graceful_restart_graceful_restart_helper_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_graceful_restart_graceful_restart_helper_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/graceful-restart/graceful-restart-disable
 */
int bgp_neighbors_unnumbered_neighbor_graceful_restart_graceful_restart_disable_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_graceful_restart_graceful_restart_disable_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/timers/advertise-interval
 */
int bgp_neighbors_unnumbered_neighbor_timers_advertise_interval_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	uint16_t routeadv;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str =
			yang_dnode_get_string(args->dnode, "../../interface");
		peer = bgp_unnumbered_neighbor_peer_lookup(
			bgp, peer_str, args->errmsg, args->errmsg_len);
		routeadv = yang_dnode_get_uint16(args->dnode, NULL);

		ret = peer_advertise_interval_set(peer, routeadv);
		bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret);

		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_timers_advertise_interval_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str =
			yang_dnode_get_string(args->dnode, "../../interface");
		peer = bgp_unnumbered_neighbor_peer_lookup(
			bgp, peer_str, args->errmsg, args->errmsg_len);

		ret = peer_advertise_interval_unset(peer);
		bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/timers/connect-time
 */
int bgp_neighbors_unnumbered_neighbor_timers_connect_time_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	uint16_t connect;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str =
			yang_dnode_get_string(args->dnode, "../../interface");
		peer = bgp_unnumbered_neighbor_peer_lookup(
			bgp, peer_str, args->errmsg, args->errmsg_len);
		connect = yang_dnode_get_uint16(args->dnode, NULL);

		ret = peer_timers_connect_set(peer, connect);
		bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret);

		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_timers_connect_time_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str =
			yang_dnode_get_string(args->dnode, "../../interface");
		peer = bgp_unnumbered_neighbor_peer_lookup(
			bgp, peer_str, args->errmsg, args->errmsg_len);
		ret = peer_timers_connect_unset(peer);
		if (bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret)
		    < 0)
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/timers/hold-time
 */
int bgp_neighbors_unnumbered_neighbor_timers_hold_time_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	uint16_t keepalive = 0;
	uint16_t holdtime = 0;
	int ret = 0;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str =
			yang_dnode_get_string(args->dnode, "../../interface");
		peer = bgp_unnumbered_neighbor_peer_lookup(
			bgp, peer_str, args->errmsg, args->errmsg_len);

		keepalive = yang_dnode_get_uint16(args->dnode, "../keepalive");
		holdtime = yang_dnode_get_uint16(args->dnode, NULL);

		if (keepalive != BGP_DEFAULT_KEEPALIVE
		    && holdtime != BGP_DEFAULT_HOLDTIME) {
			ret = peer_timers_set(peer, keepalive, holdtime);
		} else
			ret = peer_timers_unset(peer);

		if (bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret)
		    < 0)
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/timers/keepalive
 */
int bgp_neighbors_unnumbered_neighbor_timers_keepalive_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	uint16_t keepalive = 0, curr_keep = 0;
	uint16_t holdtime = 0;
	int ret = 0;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str =
			yang_dnode_get_string(args->dnode, "../../interface");
		peer = bgp_unnumbered_neighbor_peer_lookup(
			bgp, peer_str, args->errmsg, args->errmsg_len);

		keepalive = yang_dnode_get_uint16(args->dnode, NULL);
		holdtime = yang_dnode_get_uint16(args->dnode, "../hold-time");

		if (keepalive != BGP_DEFAULT_KEEPALIVE
		    && holdtime != BGP_DEFAULT_HOLDTIME) {
			if (peer->holdtime == holdtime) {
				curr_keep = (keepalive < holdtime / 3
						     ? keepalive
						     : holdtime / 3);
				if (curr_keep == keepalive)
					return NB_OK;
			}
			ret = peer_timers_set(peer, keepalive, holdtime);
		} else
			ret = peer_timers_unset(peer);

		if (bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret)
		    < 0)
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/enabled
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_enabled_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	const char *af_name;
	afi_t afi;
	safi_t safi;
	bool activate = false;
	int ret = 0;
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		af_name =
			yang_dnode_get_string(args->dnode, "../afi-safi-name");
		yang_afi_safi_identity2value(af_name, &afi, &safi);
		peer_str = yang_dnode_get_string(args->dnode,
						 "../../../interface");

		peer = bgp_unnumbered_neighbor_peer_lookup(
			bgp, peer_str, args->errmsg, args->errmsg_len);

		activate = yang_dnode_get_bool(args->dnode, NULL);

		if (activate)
			ret = peer_activate(peer, afi, safi);
		else
			ret = peer_deactivate(peer, afi, safi);

		if (bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret)
		    < 0)
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_enabled_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

static struct peer *bgp_peer_group_peer_lookup(struct bgp *bgp,
					       const char *peer_str)
{
	struct peer_group *group = NULL;

	group = peer_group_lookup(bgp, peer_str);
	return group->conf;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group
 */
int bgp_peer_groups_peer_group_create(struct nb_cb_create_args *args)
{
	const char *peer_grp_str;
	struct peer *peer;
	struct peer_group *group;
	struct bgp *bgp;
	char unnbr_xpath[XPATH_MAXLEN];
	const struct lyd_node *bgp_dnode;

	switch (args->event) {
	case NB_EV_VALIDATE:
		peer_grp_str =
			yang_dnode_get_string(args->dnode, "./peer-group-name");
		bgp_dnode = yang_dnode_get_parent(args->dnode, "bgp");
		snprintf(unnbr_xpath, sizeof(unnbr_xpath),
			 FRR_BGP_NEIGHBOR_UNNUM_XPATH, peer_grp_str, "");

		if (yang_dnode_exists(bgp_dnode, unnbr_xpath)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Name conflict with interface: %s",
				 peer_grp_str);
			return NB_ERR_VALIDATION;
		}

		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_grp_str =
			yang_dnode_get_string(args->dnode, "./peer-group-name");
		peer = peer_lookup_by_conf_if(bgp, peer_grp_str);
		if (peer) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Name conflict with interface:");
			return NB_ERR_INCONSISTENCY;
		}

		group = peer_group_get(bgp, peer_grp_str);
		if (!group) {
			snprintf(args->errmsg, args->errmsg_len,
				 "BGP failed to find or create peer-group");
			return NB_ERR_INCONSISTENCY;
		}
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_destroy(struct nb_cb_destroy_args *args)
{
	const char *peer_grp_str;
	struct peer_group *group;
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_grp_str =
			yang_dnode_get_string(args->dnode, "./peer-group-name");

		group = peer_group_lookup(bgp, peer_grp_str);
		if (group) {
			peer_group_notify_unconfig(group);
			peer_group_delete(group);
		}

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/ipv4-listen-range
 */
int bgp_peer_groups_peer_group_ipv4_listen_range_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_ipv4_listen_range_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/ipv6-listen-range
 */
int bgp_peer_groups_peer_group_ipv6_listen_range_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_ipv6_listen_range_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/password
 */
int bgp_peer_groups_peer_group_password_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	const char *passwrd_str;
	struct peer *peer = NULL;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode,
						 "../peer-group-name");
		peer = bgp_peer_group_peer_lookup(bgp, peer_str);

		passwrd_str = yang_dnode_get_string(args->dnode, NULL);
		peer_password_set(peer, passwrd_str);

		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_password_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer = NULL;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode,
						 "../peer-group-name");
		peer = bgp_peer_group_peer_lookup(bgp, peer_str);

		peer_password_unset(peer);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/ttl-security
 */
int bgp_peer_groups_peer_group_ttl_security_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	int ret;
	uint8_t gtsm_hops;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode,
						 "../peer-group-name");
		peer = bgp_peer_group_peer_lookup(bgp, peer_str);
		if (!peer)
			return NB_ERR_INCONSISTENCY;

		gtsm_hops = yang_dnode_get_uint8(args->dnode, NULL);
		/*
		 * If 'neighbor swpX', then this is for directly connected
		 * peers, we should not accept a ttl-security hops value greater
		 * than 1.
		 */
		if (peer->conf_if && (gtsm_hops > BGP_GTSM_HOPS_CONNECTED)) {
			snprintf(
				args->errmsg, args->errmsg_len,
				"%d is directly connected peer, hops cannot exceed 1\n",
				gtsm_hops);
			return NB_ERR_INCONSISTENCY;
		}

		ret = peer_ttl_security_hops_set(peer, gtsm_hops);
		if (bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret)
		    < 0)
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_ttl_security_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode,
						 "../peer-group-name");
		peer = bgp_peer_group_peer_lookup(bgp, peer_str);
		if (!peer)
			return NB_ERR_INCONSISTENCY;

		ret = peer_ttl_security_hops_unset(peer);
		if (bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret)
		    < 0)
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/solo
 */
int bgp_peer_groups_peer_group_solo_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/enforce-first-as
 */
int bgp_peer_groups_peer_group_enforce_first_as_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	bool enable = false;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode,
						 "../peer-group-name");
		peer = bgp_peer_group_peer_lookup(bgp, peer_str);

		enable = yang_dnode_get_bool(args->dnode, NULL);

		peer_flag_modify_nb(bgp, peer_str, peer,
				    PEER_FLAG_ENFORCE_FIRST_AS, enable,
				    args->errmsg, args->errmsg_len);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/description
 */
int bgp_peer_groups_peer_group_description_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	const char *desc_str;
	struct peer *peer = NULL;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode,
						 "../peer-group-name");
		peer = bgp_peer_group_peer_lookup(bgp, peer_str);

		desc_str = yang_dnode_get_string(args->dnode, NULL);

		peer_description_set(peer, desc_str);

		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_description_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer = NULL;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode,
						 "../peer-group-name");
		peer = bgp_peer_group_peer_lookup(bgp, peer_str);
		if (!peer)
			return NB_ERR_INCONSISTENCY;

		peer_description_unset(peer);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/passive-mode
 */
int bgp_peer_groups_peer_group_passive_mode_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	bool set = false;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode,
						 "../peer-group-name");
		peer = bgp_peer_group_peer_lookup(bgp, peer_str);
		if (!peer)
			return NB_ERR_INCONSISTENCY;

		set = yang_dnode_get_bool(args->dnode, NULL);

		if (peer_flag_modify_nb(bgp, peer_str, peer, PEER_FLAG_PASSIVE,
					set, args->errmsg, args->errmsg_len)
		    < 0)
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/capability-options/dynamic-capability
 */
int bgp_peer_groups_peer_group_capability_options_dynamic_capability_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	bool enable = false;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode,
						 "../../peer-group-name");
		peer = bgp_peer_group_peer_lookup(bgp, peer_str);
		if (!peer)
			return NB_ERR_INCONSISTENCY;

		enable = yang_dnode_get_bool(args->dnode, NULL);

		peer_flag_modify_nb(bgp, peer_str, peer,
				    PEER_FLAG_DYNAMIC_CAPABILITY, enable,
				    args->errmsg, args->errmsg_len);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/capability-options/strict-capability
 */
int bgp_peer_groups_peer_group_capability_options_strict_capability_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	bool enable = false;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode,
						 "../../peer-group-name");
		peer = bgp_peer_group_peer_lookup(bgp, peer_str);
		if (!peer)
			return NB_ERR_INCONSISTENCY;

		enable = yang_dnode_get_bool(args->dnode, NULL);

		peer_flag_modify_nb(bgp, peer_str, peer,
				    PEER_FLAG_STRICT_CAP_MATCH, enable,
				    args->errmsg, args->errmsg_len);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/capability-options/extended-nexthop-capability
 */
int bgp_peer_groups_peer_group_capability_options_extended_nexthop_capability_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	bool enable = false;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode,
						 "../../peer-group-name");
		peer = bgp_peer_group_peer_lookup(bgp, peer_str);
		if (!peer)
			return NB_ERR_INCONSISTENCY;

		enable = yang_dnode_get_bool(args->dnode, NULL);

		peer_flag_modify_nb(bgp, peer_str, peer,
				    PEER_FLAG_CAPABILITY_ENHE, enable,
				    args->errmsg, args->errmsg_len);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/capability-options/capability-negotiate
 */
int bgp_peer_groups_peer_group_capability_options_capability_negotiate_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/capability-options/override-capability
 */
int bgp_peer_groups_peer_group_capability_options_override_capability_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	bool enable = false;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode,
						 "../../peer-group-name");
		peer = bgp_peer_group_peer_lookup(bgp, peer_str);
		if (!peer)
			return NB_ERR_INCONSISTENCY;

		enable = yang_dnode_get_bool(args->dnode, NULL);

		peer_flag_modify_nb(bgp, peer_str, peer,
				    PEER_FLAG_OVERRIDE_CAPABILITY, enable,
				    args->errmsg, args->errmsg_len);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/update-source/ip
 */
int bgp_peer_groups_peer_group_update_source_ip_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str, *source_str;
	struct peer *peer;
	union sockunion su;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode,
						 "../../peer-group-name");
		peer = bgp_peer_group_peer_lookup(bgp, peer_str);
		if (!peer)
			return NB_ERR_INCONSISTENCY;

		source_str = yang_dnode_get_string(args->dnode, NULL);

		str2sockunion(source_str, &su);
		peer_update_source_addr_set(peer, &su);

		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_update_source_ip_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode,
						 "../../peer-group-name");
		peer = bgp_peer_group_peer_lookup(bgp, peer_str);
		if (!peer)
			return NB_ERR_INCONSISTENCY;

		peer_update_source_unset(peer);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/update-source/interface
 */
int bgp_peer_groups_peer_group_update_source_interface_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str, *source_str;
	struct peer *peer;
	struct prefix p;

	switch (args->event) {
	case NB_EV_VALIDATE:
		source_str = yang_dnode_get_string(args->dnode, NULL);
		if (str2prefix(source_str, &p)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Invalid update-source, remove prefix length");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode,
						 "../../peer-group-name");
		peer = bgp_peer_group_peer_lookup(bgp, peer_str);
		if (!peer)
			return NB_ERR_INCONSISTENCY;

		source_str = yang_dnode_get_string(args->dnode, NULL);

		peer_update_source_if_set(peer, source_str);

		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_update_source_interface_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode,
						 "../../peer-group-name");
		peer = bgp_peer_group_peer_lookup(bgp, peer_str);
		if (!peer)
			return NB_ERR_INCONSISTENCY;

		peer_update_source_unset(peer);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/neighbor-remote-as
 */
void bgp_peer_group_neighbor_remote_as_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	int as_type = AS_SPECIFIED;
	int ret;
	as_t as = 0;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	peer_str = yang_dnode_get_string(args->dnode, "../peer-group-name");
	as_type = yang_dnode_get_enum(args->dnode, "./remote-as-type");
	if (yang_dnode_exists(args->dnode, "./remote-as"))
		as = yang_dnode_get_uint32(args->dnode, "./remote-as");

	ret = peer_group_remote_as(bgp, peer_str, &as, as_type);
	if (ret < 0) {
		snprintf(args->errmsg, args->errmsg_len,
			 "Create the peer-group or interface first");
		return;
	}
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/neighbor-remote-as/remote-as-type
 */
int bgp_peer_groups_peer_group_neighbor_remote_as_remote_as_type_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_neighbor_remote_as_remote_as_type_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode,
						 "../../peer-group-name");
		group = peer_group_lookup(bgp, peer_str);
		if (group)
			peer_group_remote_as_delete(group);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/neighbor-remote-as/remote-as
 */
int bgp_peer_groups_peer_group_neighbor_remote_as_remote_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_neighbor_remote_as_remote_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/ebgp-multihop/enabled
 */
int bgp_peer_groups_peer_group_ebgp_multihop_enabled_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	bool set = false;
	int ret = 0;
	uint8_t ttl = MAXTTL;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode,
						 "../../peer-group-name");
		peer = bgp_peer_group_peer_lookup(bgp, peer_str);
		if (!peer)
			return NB_ERR_INCONSISTENCY;

		if (peer->conf_if) {
			ret = BGP_ERR_INVALID_FOR_DIRECT_PEER;
			bgp_nb_errmsg_return(args->errmsg, args->errmsg_len,
					     ret);
			return NB_ERR_INCONSISTENCY;
		}

		set = yang_dnode_get_bool(args->dnode, NULL);

		if (set)
			ret = peer_ebgp_multihop_set(peer, ttl);
		else
			ret = peer_ebgp_multihop_unset(peer);

		if (bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret)
		    < 0)
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_ebgp_multihop_enabled_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	int ret = 0;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode,
						 "../../peer-group-name");
		peer = bgp_peer_group_peer_lookup(bgp, peer_str);
		if (!peer)
			return NB_ERR_INCONSISTENCY;

		ret = peer_ebgp_multihop_unset(peer);

		if (bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret)
		    < 0)
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/ebgp-multihop/multihop-ttl
 */
int bgp_peer_groups_peer_group_ebgp_multihop_multihop_ttl_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	int ret = 0;
	uint8_t ttl = MAXTTL;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode,
						 "../../peer-group-name");
		peer = bgp_peer_group_peer_lookup(bgp, peer_str);
		if (!peer)
			return NB_ERR_INCONSISTENCY;

		if (peer->conf_if) {
			ret = BGP_ERR_INVALID_FOR_DIRECT_PEER;
			bgp_nb_errmsg_return(args->errmsg, args->errmsg_len,
					     ret);
			return NB_ERR_INCONSISTENCY;
		}

		ttl = yang_dnode_get_uint8(args->dnode, NULL);

		ret = peer_ebgp_multihop_set(peer, ttl);

		if (bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret)
		    < 0)
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_ebgp_multihop_multihop_ttl_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	int ret = 0;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode,
						 "../../peer-group-name");
		peer = bgp_peer_group_peer_lookup(bgp, peer_str);
		if (!peer)
			return NB_ERR_INCONSISTENCY;

		ret = peer_ebgp_multihop_unset(peer);

		if (bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret)
		    < 0)
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/ebgp-multihop/disable-connected-check
 */
int bgp_peer_groups_peer_group_ebgp_multihop_disable_connected_check_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	bool set = false;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode,
						 "../../peer-group-name");
		peer = bgp_peer_group_peer_lookup(bgp, peer_str);
		if (!peer)
			return NB_ERR_INCONSISTENCY;

		set = yang_dnode_get_bool(args->dnode, NULL);

		if (peer_flag_modify_nb(bgp, peer_str, peer,
					PEER_FLAG_DISABLE_CONNECTED_CHECK, set,
					args->errmsg, args->errmsg_len)
		    < 0)
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/local-as
 */
void bgp_peer_groups_peer_group_local_as_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	struct bgp *bgp;
	int ret;
	as_t as = 0;
	const char *peer_str;
	struct peer *peer = NULL;
	bool no_prepend = false;
	bool replace_as = false;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	peer_str = yang_dnode_get_string(args->dnode, "../peer-group-name");

	peer = bgp_peer_group_peer_lookup(bgp, peer_str);

	if (yang_dnode_exists(args->dnode, "./local-as"))
		as = yang_dnode_get_uint32(args->dnode, "./local-as");

	if (yang_dnode_exists(args->dnode, "./local-as"))
		as = yang_dnode_get_uint32(args->dnode, "./local-as");
	if (yang_dnode_exists(args->dnode, "./no-prepend"))
		no_prepend = yang_dnode_get_bool(args->dnode, "./no-prepend");
	if (yang_dnode_exists(args->dnode, "./no-replace-as"))
		replace_as =
			yang_dnode_get_bool(args->dnode, "./no-replace-as");

	if (!as && !no_prepend && !replace_as)
		ret = peer_local_as_unset(peer);
	else
		ret = peer_local_as_set(peer, as, no_prepend, replace_as);

	bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret);
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/local-as/local-as
 */
int bgp_peer_groups_peer_group_local_as_local_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_local_as_local_as_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode,
						 "../../peer-group-name");
		peer = bgp_peer_group_peer_lookup(bgp, peer_str);

		ret = peer_local_as_unset(peer);
		if (bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret)
		    < 0)
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/local-as/no-prepend
 */
int bgp_peer_groups_peer_group_local_as_no_prepend_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_local_as_no_prepend_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/local-as/no-replace-as
 */
int bgp_peer_groups_peer_group_local_as_no_replace_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/bfd-options/enable
 */
int bgp_peer_groups_peer_group_bfd_options_enable_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/bfd-options/detect-multiplier
 */
int bgp_peer_groups_peer_group_bfd_options_detect_multiplier_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_bfd_options_detect_multiplier_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/bfd-options/required-min-rx
 */
int bgp_peer_groups_peer_group_bfd_options_required_min_rx_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_bfd_options_required_min_rx_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/bfd-options/desired-min-tx
 */
int bgp_peer_groups_peer_group_bfd_options_desired_min_tx_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_bfd_options_desired_min_tx_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/bfd-options/session-type
 */
int bgp_peer_groups_peer_group_bfd_options_session_type_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_bfd_options_session_type_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/bfd-options/check-cp-failure
 */
int bgp_peer_groups_peer_group_bfd_options_check_cp_failure_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_bfd_options_check_cp_failure_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/admin-shutdown
 */
void bgp_peer_groups_peer_group_admin_shutdown_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	bool enable = false;
	const char *message;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	peer_str = yang_dnode_get_string(args->dnode, "../peer-group-name");
	peer = bgp_peer_group_peer_lookup(bgp, peer_str);

	if (yang_dnode_exists(args->dnode, "./message")) {
		message = yang_dnode_get_string(args->dnode, "./message");
		peer_tx_shutdown_message_set(peer, message);
	}
	enable = yang_dnode_get_bool(args->dnode, "./enable");

	peer_flag_modify_nb(bgp, peer_str, peer, PEER_FLAG_SHUTDOWN, enable,
			    args->errmsg, args->errmsg_len);
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/admin-shutdown/enable
 */
int bgp_peer_groups_peer_group_admin_shutdown_enable_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_admin_shutdown_enable_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/admin-shutdown/message
 */
int bgp_peer_groups_peer_group_admin_shutdown_message_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_admin_shutdown_message_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/graceful-restart/enable
 */
int bgp_peer_groups_peer_group_graceful_restart_enable_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_graceful_restart_enable_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/graceful-restart/graceful-restart-helper
 */
int bgp_peer_groups_peer_group_graceful_restart_graceful_restart_helper_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_graceful_restart_graceful_restart_helper_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/graceful-restart/graceful-restart-disable
 */
int bgp_peer_groups_peer_group_graceful_restart_graceful_restart_disable_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_graceful_restart_graceful_restart_disable_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/timers/advertise-interval
 */
int bgp_peer_groups_peer_group_timers_advertise_interval_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	uint16_t routeadv;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode,
						 "../../peer-group-name");
		peer = bgp_peer_group_peer_lookup(bgp, peer_str);
		routeadv = yang_dnode_get_uint16(args->dnode, NULL);

		ret = peer_advertise_interval_set(peer, routeadv);
		if (bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret)
		    < 0)
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_timers_advertise_interval_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode,
						 "../../peer-group-name");
		peer = bgp_peer_group_peer_lookup(bgp, peer_str);

		ret = peer_advertise_interval_unset(peer);
		if (bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret)
		    < 0)
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/timers/connect-time
 */
int bgp_peer_groups_peer_group_timers_connect_time_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	uint16_t connect;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode,
						 "../../peer-group-name");
		peer = bgp_peer_group_peer_lookup(bgp, peer_str);
		connect = yang_dnode_get_uint16(args->dnode, NULL);

		ret = peer_timers_connect_set(peer, connect);
		if (bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret)
		    < 0)
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_timers_connect_time_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode,
						 "../../peer-group-name");
		peer = bgp_peer_group_peer_lookup(bgp, peer_str);

		ret = peer_timers_connect_unset(peer);
		if (bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret)
		    < 0)
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/timers/hold-time
 */
int bgp_peer_groups_peer_group_timers_hold_time_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	uint16_t keepalive = 0;
	uint16_t holdtime = 0;
	int ret = 0;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode,
						 "../../peer-group-name");
		peer = bgp_peer_group_peer_lookup(bgp, peer_str);

		keepalive = yang_dnode_get_uint16(args->dnode, "../keepalive");
		holdtime = yang_dnode_get_uint16(args->dnode, NULL);

		if (keepalive != BGP_DEFAULT_KEEPALIVE
		    && holdtime != BGP_DEFAULT_HOLDTIME) {
			ret = peer_timers_set(peer, keepalive, holdtime);
		} else
			ret = peer_timers_unset(peer);

		if (bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret)
		    < 0)
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/timers/keepalive
 */
int bgp_peer_groups_peer_group_timers_keepalive_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	uint16_t keepalive = 0, curr_keep = 0;
	uint16_t holdtime = 0;
	int ret = 0;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		peer_str = yang_dnode_get_string(args->dnode,
						 "../../peer-group-name");
		peer = bgp_peer_group_peer_lookup(bgp, peer_str);

		keepalive = yang_dnode_get_uint16(args->dnode, NULL);
		holdtime = yang_dnode_get_uint16(args->dnode, "../hold-time");

		if (keepalive != BGP_DEFAULT_KEEPALIVE
		    && holdtime != BGP_DEFAULT_HOLDTIME) {
			if (peer->holdtime == holdtime) {
				curr_keep = (keepalive < holdtime / 3
						     ? keepalive
						     : holdtime / 3);
				if (curr_keep == keepalive) {
					// zlog_debug("%s holdtime %u keepalive
					// %u value is already set, skipping
					// update.",
					//   __func__, holdtime, keepalive);
					return NB_OK;
				}
			}
			ret = peer_timers_set(peer, keepalive, holdtime);
		} else
			ret = peer_timers_unset(peer);

		if (bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret)
		    < 0)
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/enabled
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_enabled_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	const char *af_name;
	afi_t afi;
	safi_t safi;
	bool activate = false;
	int ret = 0;
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		bgp = nb_running_get_entry(args->dnode, NULL, true);
		af_name =
			yang_dnode_get_string(args->dnode, "../afi-safi-name");
		yang_afi_safi_identity2value(af_name, &afi, &safi);
		peer_str = yang_dnode_get_string(args->dnode,
						 "../../../peer-group-name");
		peer = bgp_peer_group_peer_lookup(bgp, peer_str);

		activate = yang_dnode_get_bool(args->dnode, NULL);
		if (activate)
			ret = peer_activate(peer, afi, safi);
		else
			ret = peer_deactivate(peer, afi, safi);

		if (bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret)
		    < 0)
			return NB_ERR_INCONSISTENCY;

		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_enabled_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

void bgp_global_afi_safis_afi_safi_network_config_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	const struct lyd_node *af_dnode;
	struct bgp *bgp;
	const char *af_name;
	struct prefix prefix;
	bool is_backdoor = false;
	uint32_t label_index = BGP_INVALID_LABEL_INDEX;
	const char *rmap_name = NULL;
	afi_t afi;
	safi_t safi;

	af_dnode = yang_dnode_get_parent(args->dnode, "afi-safi");
	af_name = yang_dnode_get_string(af_dnode, "./afi-safi-name");
	yang_afi_safi_identity2value(af_name, &afi, &safi);
	bgp = nb_running_get_entry(af_dnode, NULL, true);

	yang_dnode_get_prefix(&prefix, args->dnode, "./prefix");

	is_backdoor = yang_dnode_get_bool(args->dnode, "./backdoor");

	if (yang_dnode_exists(args->dnode, "./label-index"))
		label_index =
			yang_dnode_get_uint32(args->dnode, "./label-index");

	if (yang_dnode_exists(args->dnode, "./rmap-policy-export"))
		rmap_name = yang_dnode_get_string(args->dnode,
						  "./rmap-policy-export");

	bgp_static_set(bgp, NULL, &prefix, afi, safi, rmap_name, is_backdoor,
		       label_index, args->errmsg, args->errmsg_len);
}

static int bgp_global_afi_safis_afi_safi_network_config_destroy(
	struct nb_cb_destroy_args *args)
{
	const struct lyd_node *af_dnode;
	struct bgp *bgp;
	const char *af_name;
	struct prefix prefix;
	uint32_t label_index = BGP_INVALID_LABEL_INDEX;
	const char *rmap_name = NULL;
	bool is_backdoor = false;
	afi_t afi;
	safi_t safi;
	int ret;

	af_dnode = yang_dnode_get_parent(args->dnode, "afi-safi");
	af_name = yang_dnode_get_string(af_dnode, "./afi-safi-name");
	yang_afi_safi_identity2value(af_name, &afi, &safi);
	bgp = nb_running_get_entry(af_dnode, NULL, true);

	yang_dnode_get_prefix(&prefix, args->dnode, "./prefix");

	if (yang_dnode_exists(args->dnode, "./rmap-policy-export"))
		rmap_name = yang_dnode_get_string(args->dnode,
						  "./rmap-policy-export");

	if (yang_dnode_exists(args->dnode, "./label-index"))
		label_index =
			yang_dnode_get_uint32(args->dnode, "./label-index");

	if (yang_dnode_exists(args->dnode, "./backdoor"))
		is_backdoor = yang_dnode_get_bool(args->dnode, "./backdoor");

	ret = bgp_static_set(bgp, "no", &prefix, afi, safi, rmap_name,
			     is_backdoor, label_index, args->errmsg,
			     args->errmsg_len);
	if (ret < 0)
		return NB_ERR_INCONSISTENCY;

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/network-config
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_network_config_create(
	struct nb_cb_create_args *args)
{
	/* Handled in network_config_apply_finish callback */

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_unicast_network_config_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_global_afi_safis_afi_safi_network_config_destroy(
			args);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/network-config/backdoor
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_network_config_backdoor_modify(
	struct nb_cb_modify_args *args)
{
	/* Handled in unicast_network_config_apply_finish callback */

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/network-config/label-index
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_network_config_label_index_modify(
	struct nb_cb_modify_args *args)
{
	const struct lyd_node *af_dnode;
	struct bgp *bgp;
	const char *af_name;
	struct prefix prefix;
	uint32_t label_index;
	afi_t afi;
	safi_t safi;
	struct bgp_dest *dest;
	struct bgp_static *bgp_static;

	switch (args->event) {
	case NB_EV_VALIDATE:
		bgp = nb_running_get_entry(args->dnode, NULL, false);
		if (!bgp)
			return NB_OK;

		af_dnode = yang_dnode_get_parent(args->dnode, "afi-safi");
		af_name = yang_dnode_get_string(af_dnode, "./afi-safi-name");
		yang_afi_safi_identity2value(af_name, &afi, &safi);
		yang_dnode_get_prefix(&prefix, args->dnode, "../prefix");
		apply_mask(&prefix);

		label_index = yang_dnode_get_uint32(args->dnode, NULL);

		dest = bgp_node_get(bgp->route[afi][safi], &prefix);
		bgp_static = bgp_dest_get_bgp_static_info(dest);
		if (bgp_static) {
			if (bgp_static->label_index != label_index) {
				snprintf(
					args->errmsg, args->errmsg_len,
					"Cannot change label-index: curr %u input %u\n",
					bgp_static->label_index, label_index);
				return NB_ERR_VALIDATION;
			}
		}

		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_unicast_network_config_label_index_destroy(
	struct nb_cb_destroy_args *args)
{
	/* Handled in unicast_network_config_apply_finish callback */

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/network-config/rmap-policy-export
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_network_config_rmap_policy_export_modify(
	struct nb_cb_modify_args *args)
{
	/* Handled in unicast_network_config_apply_finish callback */

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_unicast_network_config_rmap_policy_export_destroy(
	struct nb_cb_destroy_args *args)
{
	/* rmap destory alone is not supported by backend, the entire network
	 * config needs to be destroyed.
	 */
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

void bgp_global_afi_safi_aggregate_route_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	const struct lyd_node *af_dnode;
	struct bgp *bgp;
	const char *af_name;
	struct prefix prefix;
	const char *rmap_name = NULL;
	afi_t afi;
	safi_t safi;
	uint8_t as_set = 0;
	int summary_only = 0;
	uint8_t origin = BGP_ORIGIN_UNSPECIFIED;
	bool match_med = false;
	const char *suppress_map = NULL;

	af_dnode = yang_dnode_get_parent(args->dnode, "afi-safi");
	af_name = yang_dnode_get_string(af_dnode, "./afi-safi-name");
	yang_afi_safi_identity2value(af_name, &afi, &safi);
	bgp = nb_running_get_entry(af_dnode, NULL, true);

	yang_dnode_get_prefix(&prefix, args->dnode, "./prefix");

	if (yang_dnode_exists(args->dnode, "./as-set"))
		as_set = yang_dnode_get_bool(args->dnode, "./as-set");

	summary_only = yang_dnode_get_bool(args->dnode, "./summary-only");

	if (yang_dnode_exists(args->dnode, "./rmap-policy-export"))
		rmap_name = yang_dnode_get_string(args->dnode,
						  "./rmap-policy-export");

	origin = yang_dnode_get_enum(args->dnode, "./origin");
	match_med = yang_dnode_get_bool(args->dnode, "./match-med");
	if (yang_dnode_exists(args->dnode, "./suppress-map"))
		suppress_map =
			yang_dnode_get_string(args->dnode, "./suppress-map");

	bgp_aggregate_set(bgp, &prefix, afi, safi, rmap_name, summary_only,
			  as_set, origin, match_med, suppress_map, args->errmsg,
			  args->errmsg_len);
}

static int
bgp_global_afi_safi_aggregate_route_destroy(struct nb_cb_destroy_args *args)
{
	const struct lyd_node *af_dnode;
	struct bgp *bgp;
	const char *af_name;
	struct prefix prefix;
	afi_t afi;
	safi_t safi;
	int ret;

	af_dnode = yang_dnode_get_parent(args->dnode, "afi-safi");
	af_name = yang_dnode_get_string(af_dnode, "./afi-safi-name");
	yang_afi_safi_identity2value(af_name, &afi, &safi);
	bgp = nb_running_get_entry(af_dnode, NULL, true);

	yang_dnode_get_prefix(&prefix, args->dnode, "./prefix");

	ret = bgp_aggregate_unset(bgp, &prefix, afi, safi, args->errmsg,
				  args->errmsg_len);

	if (ret < 0)
		return NB_ERR_INCONSISTENCY;

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/aggregate-route
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_aggregate_route_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_unicast_aggregate_route_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_global_afi_safi_aggregate_route_destroy(args);
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/aggregate-route/as-set
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_aggregate_route_as_set_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/aggregate-route/summary-only
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_aggregate_route_summary_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/aggregate-route/rmap-policy-export
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_aggregate_route_rmap_policy_export_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_unicast_aggregate_route_rmap_policy_export_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/aggregate-route/origin
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_aggregate_route_origin_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/aggregate-route/match-med
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_aggregate_route_match_med_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/aggregate-route/suppress-map
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_aggregate_route_suppress_map_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_unicast_aggregate_route_suppress_map_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

void bgp_global_afi_safi_admin_distance_route_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	const struct lyd_node *af_dnode;
	const char *af_name;
	const char *prefix_str = NULL;
	const char *access_list_str = NULL;
	uint8_t distance;
	afi_t afi;
	safi_t safi;

	af_dnode = yang_dnode_get_parent(args->dnode, "afi-safi");
	af_name = yang_dnode_get_string(af_dnode, "./afi-safi-name");
	yang_afi_safi_identity2value(af_name, &afi, &safi);

	prefix_str = yang_dnode_get_string(args->dnode, "./prefix");
	distance = yang_dnode_get_uint8(args->dnode, "./distance");
	if (yang_dnode_exists(args->dnode, "./access-list-policy-export"))
		access_list_str = yang_dnode_get_string(
			args->dnode, "./access-list-policy-export");

	bgp_distance_set(distance, prefix_str, access_list_str, afi, safi,
			 args->errmsg, args->errmsg_len);
}

static int bgp_global_afi_safi_admin_distance_route_destroy(
	struct nb_cb_destroy_args *args)
{
	const struct lyd_node *af_dnode;
	const char *af_name;
	const char *prefix_str = NULL;
	const char *access_list_str = NULL;
	uint8_t distance;
	afi_t afi;
	safi_t safi;

	af_dnode = yang_dnode_get_parent(args->dnode, "afi-safi");
	af_name = yang_dnode_get_string(af_dnode, "./afi-safi-name");
	yang_afi_safi_identity2value(af_name, &afi, &safi);

	prefix_str = yang_dnode_get_string(args->dnode, "./prefix");
	distance = yang_dnode_get_uint8(args->dnode, "./distance");
	if (yang_dnode_exists(args->dnode, "./access-list-policy-export"))
		access_list_str = yang_dnode_get_string(
			args->dnode, "./access-list-policy-export");

	if (bgp_distance_unset(distance, prefix_str, access_list_str, afi, safi,
			       args->errmsg, args->errmsg_len)
	    != CMD_SUCCESS)
		return NB_ERR_INCONSISTENCY;

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/admin-distance-route
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_admin_distance_route_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_unicast_admin_distance_route_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_global_afi_safi_admin_distance_route_destroy(args);
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/admin-distance-route/distance
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_admin_distance_route_distance_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/admin-distance-route/access-list-policy-export
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_admin_distance_route_access_list_policy_export_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_unicast_admin_distance_route_access_list_policy_export_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

void bgp_global_afi_safis_afi_safi_route_flap_dampening_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	const struct lyd_node *af_dnode;
	struct bgp *bgp;
	const char *af_name;
	afi_t afi;
	safi_t safi;
	int half = DEFAULT_HALF_LIFE * 60;
	int reuse = DEFAULT_REUSE;
	int suppress = DEFAULT_SUPPRESS;
	int max;
	char ab_xpath[XPATH_MAXLEN];

	af_dnode = yang_dnode_get_parent(args->dnode, "afi-safi");
	af_name = yang_dnode_get_string(af_dnode, "./afi-safi-name");
	yang_afi_safi_identity2value(af_name, &afi, &safi);
	bgp = nb_running_get_entry(af_dnode, NULL, true);

	if (!yang_dnode_get_bool(args->dnode, "./enable")) {
		bgp_damp_disable(bgp, afi, safi);
	} else {
		half = yang_dnode_get_uint8(args->dnode, "./reach-decay");
		half *= 60;
		reuse = yang_dnode_get_uint16(args->dnode, "./reuse-above");

		suppress =
			yang_dnode_get_uint16(args->dnode, "./suppress-above");

		max = yang_dnode_get_uint8(args->dnode, "./unreach-decay");
		yang_dnode_get_path(args->dnode, ab_xpath, sizeof(ab_xpath));
		strlcat(ab_xpath, "/unreach-decay", sizeof(ab_xpath));
		if (yang_get_default_uint8(ab_xpath) == max)
			max = half * 4;
		else
			max *= 60;

		bgp_damp_enable(bgp, afi, safi, half, reuse, suppress, max);
	}
}

static int
bgp_global_afi_safi_route_flap_validation(struct nb_cb_modify_args *args)
{
	int reuse;
	int suppress;

	if (yang_dnode_exists(args->dnode, "../suppress-above")
	    && yang_dnode_exists(args->dnode, "../reuse-above")) {
		suppress =
			yang_dnode_get_uint16(args->dnode, "../suppress-above");
		reuse = yang_dnode_get_uint16(args->dnode, "../reuse-above");
		if (suppress < reuse) {
			snprintf(
				args->errmsg, args->errmsg_len,
				"Suppress value cannot be less than reuse value \n");
			return NB_ERR_VALIDATION;
		}
	}
	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/route-flap-dampening/enable
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_route_flap_dampening_enable_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		return bgp_global_afi_safi_route_flap_validation(args);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/route-flap-dampening/reach-decay
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_route_flap_dampening_reach_decay_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_unicast_route_flap_dampening_reach_decay_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/route-flap-dampening/reuse-above
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_route_flap_dampening_reuse_above_modify(
	struct nb_cb_modify_args *args)
{
	int reuse = DEFAULT_REUSE;
	int suppress = DEFAULT_SUPPRESS;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (yang_dnode_exists(args->dnode, "../suppress-above"))
			suppress = yang_dnode_get_uint16(args->dnode,
							 "../suppress-above");
		reuse = yang_dnode_get_uint16(args->dnode, "../reuse-above");
		if (suppress < reuse) {
			snprintf(
				args->errmsg, args->errmsg_len,
				"Suppress value cannot be less than reuse value \n");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_unicast_route_flap_dampening_reuse_above_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/route-flap-dampening/suppress-above
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_route_flap_dampening_suppress_above_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_unicast_route_flap_dampening_suppress_above_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/route-flap-dampening/unreach-decay
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_route_flap_dampening_unreach_decay_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_unicast_route_flap_dampening_unreach_decay_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

static int
bgp_global_afi_safi_ip_unicast_use_multiple_paths_ebgp_maximum_paths_modify(
	struct nb_cb_modify_args *args)
{
	const struct lyd_node *af_dnode;
	struct bgp *bgp;
	const char *af_name;
	afi_t afi;
	safi_t safi;
	uint16_t maxpaths, default_maxpaths;
	int ret;
	char xpath[XPATH_MAXLEN];
	char afi_xpath[XPATH_MAXLEN];

	af_dnode = yang_dnode_get_parent(args->dnode, "afi-safi");
	af_name = yang_dnode_get_string(af_dnode, "./afi-safi-name");
	yang_afi_safi_identity2value(af_name, &afi, &safi);
	bgp = nb_running_get_entry(af_dnode, NULL, true);
	maxpaths = yang_dnode_get_uint16(args->dnode, NULL);

	snprintf(xpath, sizeof(xpath), FRR_BGP_GLOBAL_XPATH, "frr-bgp:bgp",
		 "bgp", bgp->name ? bgp->name : VRF_DEFAULT_NAME);
	snprintf(
		afi_xpath, sizeof(afi_xpath),
		"/global/afi-safis/afi-safi[afi-safi-name='%s']/%s/use-multiple-paths/ebgp/maximum-paths",
		yang_afi_safi_value2identity(afi, safi),
		bgp_afi_safi_get_container_str(afi, safi));
	strlcat(xpath, afi_xpath, sizeof(xpath));
	default_maxpaths = yang_get_default_uint16(xpath);

	ret = bgp_maxpaths_config_vty(bgp, afi, safi, BGP_PEER_EBGP, maxpaths,
				      0, maxpaths != default_maxpaths ? 1 : 0,
				      args->errmsg, args->errmsg_len);
	if (ret != CMD_SUCCESS)
		return NB_ERR_INCONSISTENCY;

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/use-multiple-paths/ebgp/maximum-paths
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_use_multiple_paths_ebgp_maximum_paths_modify(
	struct nb_cb_modify_args *args)
{
	uint16_t maxpaths;

	switch (args->event) {
	case NB_EV_VALIDATE:
		maxpaths = yang_dnode_get_uint16(args->dnode, NULL);
		if (maxpaths > multipath_num) {
			snprintf(args->errmsg, args->errmsg_len,
				 "maxpaths %u is out of range %u", maxpaths,
				 multipath_num);
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_global_afi_safi_ip_unicast_use_multiple_paths_ebgp_maximum_paths_modify(
			args);
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/use-multiple-paths/ibgp
 */
void bgp_global_afi_safi_ip_unicast_use_multiple_paths_ibgp_maximum_paths_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	const struct lyd_node *af_dnode;
	struct bgp *bgp;
	const char *af_name;
	afi_t afi;
	safi_t safi;
	uint16_t maxpaths, default_maxpaths;
	char xpath[XPATH_MAXLEN];
	char afi_xpath[XPATH_MAXLEN];
	uint16_t options = 0;

	af_dnode = yang_dnode_get_parent(args->dnode, "afi-safi");
	af_name = yang_dnode_get_string(af_dnode, "./afi-safi-name");
	yang_afi_safi_identity2value(af_name, &afi, &safi);
	bgp = nb_running_get_entry(af_dnode, NULL, true);

	maxpaths = yang_dnode_get_uint16(args->dnode, "./maximum-paths");
	if (yang_dnode_get_bool(args->dnode, "./cluster-length-list"))
		options = BGP_FLAG_IBGP_MULTIPATH_SAME_CLUSTERLEN;

	snprintf(xpath, sizeof(xpath), FRR_BGP_GLOBAL_XPATH, "frr-bgp:bgp",
		 "bgp", bgp->name ? bgp->name : VRF_DEFAULT_NAME);
	snprintf(
		afi_xpath, sizeof(afi_xpath),
		"/global/afi-safis/afi-safi[afi-safi-name='%s']/%s/use-multiple-paths/ibgp/maximum-paths",
		yang_afi_safi_value2identity(afi, safi),
		bgp_afi_safi_get_container_str(afi, safi));
	strlcat(xpath, afi_xpath, sizeof(xpath));
	default_maxpaths = yang_get_default_uint16(xpath);

	bgp_maxpaths_config_vty(bgp, afi, safi, BGP_PEER_IBGP, maxpaths,
				options, maxpaths != default_maxpaths ? 1 : 0,
				args->errmsg, args->errmsg_len);
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/use-multiple-paths/ibgp/maximum-paths
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_use_multiple_paths_ibgp_maximum_paths_modify(
	struct nb_cb_modify_args *args)
{
	uint16_t maxpaths;

	switch (args->event) {
	case NB_EV_VALIDATE:
		maxpaths = yang_dnode_get_uint16(args->dnode, NULL);
		if (maxpaths > multipath_num) {
			snprintf(args->errmsg, args->errmsg_len,
				 "maxpaths %u is out of range %u", maxpaths,
				 multipath_num);
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/use-multiple-paths/ibgp/cluster-length-list
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_use_multiple_paths_ibgp_cluster_length_list_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_unicast_use_multiple_paths_ibgp_cluster_length_list_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

void bgp_global_afi_safi_ip_unicast_redistribution_list_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	const struct lyd_node *af_dnode;
	struct bgp *bgp;
	const char *af_name;
	afi_t afi;
	safi_t safi;
	int route_type;
	int route_instance;
	struct bgp_redist *red;
	bool changed = false;
	struct route_map *route_map = NULL;
	const char *rmap_name = NULL;
	uint32_t metric = 0;

	af_dnode = yang_dnode_get_parent(args->dnode, "afi-safi");
	af_name = yang_dnode_get_string(af_dnode, "./afi-safi-name");
	yang_afi_safi_identity2value(af_name, &afi, &safi);
	bgp = nb_running_get_entry(af_dnode, NULL, true);

	route_type = yang_dnode_get_enum(args->dnode, "./route-type");
	route_instance = yang_dnode_get_uint16(args->dnode, "./route-instance");

	red = bgp_redist_add(bgp, afi, route_type, route_instance);

	if (yang_dnode_exists(args->dnode, "./rmap-policy-import")) {
		rmap_name = yang_dnode_get_string(args->dnode,
						  "./rmap-policy-import");
		route_map = route_map_lookup_by_name(rmap_name);

		changed = bgp_redistribute_rmap_set(red, rmap_name, route_map);
	}

	if (yang_dnode_exists(args->dnode, "./metric")) {
		metric = yang_dnode_get_uint32(args->dnode, "./metric");
		changed |= bgp_redistribute_metric_set(bgp, red, afi,
						       route_type, metric);
	}

	bgp_redistribute_set(bgp, afi, route_type, route_instance, changed);
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/redistribution-list
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_redistribution_list_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_unicast_redistribution_list_destroy(
	struct nb_cb_destroy_args *args)
{
	const struct lyd_node *af_dnode;
	struct bgp *bgp;
	const char *af_name;
	afi_t afi;
	safi_t safi;
	int route_type;
	int route_instance;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		af_dnode = yang_dnode_get_parent(args->dnode, "afi-safi");
		af_name = yang_dnode_get_string(af_dnode, "./afi-safi-name");
		yang_afi_safi_identity2value(af_name, &afi, &safi);
		bgp = nb_running_get_entry(af_dnode, NULL, true);

		route_type = yang_dnode_get_enum(args->dnode, "./route-type");
		route_instance =
			yang_dnode_get_uint16(args->dnode, "./route-instance");

		bgp_redistribute_unset(bgp, afi, route_type, route_instance);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/redistribution-list/metric
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_redistribution_list_metric_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_unicast_redistribution_list_metric_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/redistribution-list/rmap-policy-import
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_redistribution_list_rmap_policy_import_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_unicast_redistribution_list_rmap_policy_import_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

static int
bgp_global_afi_safis_admin_distance_modify(struct nb_cb_apply_finish_args *args)
{
	struct bgp *bgp;
	const struct lyd_node *af_dnode;
	const char *af_name;
	afi_t afi;
	safi_t safi;
	uint8_t distance_ebgp, distance_ibgp, distance_local;

	af_dnode = yang_dnode_get_parent(args->dnode, "afi-safi");
	af_name = yang_dnode_get_string(af_dnode, "./afi-safi-name");
	yang_afi_safi_identity2value(af_name, &afi, &safi);
	bgp = nb_running_get_entry(af_dnode, NULL, true);

	distance_ebgp = yang_dnode_get_uint8(args->dnode, "./external");
	distance_ibgp = yang_dnode_get_uint8(args->dnode, "./internal");
	distance_local = yang_dnode_get_uint8(args->dnode, "./local");

	bgp->distance_ebgp[afi][safi] = distance_ebgp;
	bgp->distance_ibgp[afi][safi] = distance_ibgp;
	bgp->distance_local[afi][safi] = distance_local;

	bgp_announce_routes_distance_update(bgp, afi, safi);

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/admin-distance
 */
void bgp_global_afi_safis_afi_safi_ipv4_unicast_admin_distance_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	bgp_global_afi_safis_admin_distance_modify(args);
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/admin-distance/external
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_admin_distance_external_modify(
	struct nb_cb_modify_args *args)
{
	/* Handled in admin_distance_apply_finish callback */

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/admin-distance/internal
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_admin_distance_internal_modify(
	struct nb_cb_modify_args *args)
{
	/* Handled in admin_distance_apply_finish callback */

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/admin-distance/local
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_admin_distance_local_modify(
	struct nb_cb_modify_args *args)
{
	/* Handled in admin_distance_apply_finish callback */

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/filter-config/rmap-export
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_export_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_export_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

static int bgp_global_afi_safi_ip_unicast_vpn_config_rd_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const struct lyd_node *af_dnode;
	const char *af_name;
	afi_t afi;
	safi_t safi;
	const char *rd_str = NULL;
	struct prefix_rd prd;

	bgp = nb_running_get_entry(args->dnode, NULL, true);

	af_dnode = yang_dnode_get_parent(args->dnode, "afi-safi");
	af_name = yang_dnode_get_string(af_dnode, "./afi-safi-name");
	yang_afi_safi_identity2value(af_name, &afi, &safi);

	rd_str = yang_dnode_get_string(args->dnode, NULL);
	if (!str2prefix_rd(rd_str, &prd)) {
		snprintf(args->errmsg, args->errmsg_len, "Malformed rd %s\n",
			 rd_str);
		return NB_ERR_INCONSISTENCY;
	}

	/*
	 * pre-change: un-export vpn routes (vpn->vrf routes unaffected)
	 */
	vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(),
			   bgp);

	bgp->vpn_policy[afi].tovpn_rd = prd;
	SET_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_RD_SET);

	/* post-change: re-export vpn routes */
	vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(),
			    bgp);

	return NB_OK;
}

static int bgp_global_afi_safi_ip_unicast_vpn_config_rd_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const struct lyd_node *af_dnode;
	const char *af_name;
	afi_t afi;
	safi_t safi;
	const char *rd_str = NULL;
	struct prefix_rd prd;

	af_dnode = yang_dnode_get_parent(args->dnode, "afi-safi");
	af_name = yang_dnode_get_string(af_dnode, "./afi-safi-name");
	yang_afi_safi_identity2value(af_name, &afi, &safi);
	bgp = nb_running_get_entry(af_dnode, NULL, true);

	rd_str = yang_dnode_get_string(args->dnode, NULL);
	if (str2prefix_rd(rd_str, &prd)) {
		snprintf(args->errmsg, args->errmsg_len, "Malformed rd %s \n",
			 rd_str);
		return NB_ERR_INCONSISTENCY;
	}

	/*
	 * pre-change: un-export vpn routes (vpn->vrf routes unaffected)
	 */
	vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(),
			   bgp);

	UNSET_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_RD_SET);

	/* post-change: re-export vpn routes */
	vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(),
			    bgp);
	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/rd
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_rd_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const struct lyd_node *af_dnode;
	const char *af_name;
	afi_t afi;
	safi_t safi;

	switch (args->event) {
	case NB_EV_VALIDATE:
		bgp = nb_running_get_entry(args->dnode, NULL, false);
		if (!bgp)
			return NB_OK;

		af_dnode = yang_dnode_get_parent(args->dnode, "afi-safi");
		af_name = yang_dnode_get_string(af_dnode, "./afi-safi-name");
		yang_afi_safi_identity2value(af_name, &afi, &safi);

		if (!vpn_policy_check_import(bgp, afi, safi, false,
					     args->errmsg, args->errmsg_len))
			return NB_ERR_VALIDATION;
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:

		return bgp_global_afi_safi_ip_unicast_vpn_config_rd_modify(
			args);

		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_rd_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_global_afi_safi_ip_unicast_vpn_config_rd_destroy(
			args);
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/label
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_label_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_label_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/label-auto
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_label_auto_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_label_auto_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

static int bgp_global_afi_safi_ip_unicast_vpn_config_nexthop_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const struct lyd_node *af_dnode;
	const char *af_name;
	afi_t afi;
	safi_t safi;
	struct prefix p;

	af_dnode = yang_dnode_get_parent(args->dnode, "afi-safi");
	af_name = yang_dnode_get_string(af_dnode, "./afi-safi-name");
	yang_afi_safi_identity2value(af_name, &afi, &safi);
	bgp = nb_running_get_entry(af_dnode, NULL, true);

	yang_dnode_get_prefix(&p, args->dnode, NULL);

	/*
	 * pre-change: un-export vpn routes (vpn->vrf routes unaffected)
	 */
	vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(),
			   bgp);

	bgp->vpn_policy[afi].tovpn_nexthop = p;
	SET_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_NEXTHOP_SET);

	/* post-change: re-export vpn routes */
	vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(),
			    bgp);

	return NB_OK;
}

static int bgp_global_afi_safi_ip_unicast_vpn_config_nexthop_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const struct lyd_node *af_dnode;
	const char *af_name;
	afi_t afi;
	safi_t safi;
	struct prefix p;

	af_dnode = yang_dnode_get_parent(args->dnode, "afi-safi");
	af_name = yang_dnode_get_string(af_dnode, "./afi-safi-name");
	yang_afi_safi_identity2value(af_name, &afi, &safi);
	bgp = nb_running_get_entry(af_dnode, NULL, true);

	yang_dnode_get_prefix(&p, args->dnode, NULL);

	/*
	 * pre-change: un-export vpn routes (vpn->vrf routes unaffected)
	 */
	vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(),
			   bgp);
	UNSET_FLAG(bgp->vpn_policy[afi].flags,
		   BGP_VPN_POLICY_TOVPN_NEXTHOP_SET);
	/* post-change: re-export vpn routes */
	vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(),
			    bgp);
	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/nexthop
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_nexthop_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const struct lyd_node *af_dnode;
	const char *af_name;
	afi_t afi;
	safi_t safi;

	switch (args->event) {
	case NB_EV_VALIDATE:
		bgp = nb_running_get_entry(args->dnode, NULL, false);
		if (!bgp)
			return NB_OK;
		af_dnode = yang_dnode_get_parent(args->dnode, "afi-safi");
		af_name = yang_dnode_get_string(af_dnode, "./afi-safi-name");
		yang_afi_safi_identity2value(af_name, &afi, &safi);

		if (!vpn_policy_check_import(bgp, afi, safi, false,
					     args->errmsg, args->errmsg_len))
			return NB_ERR_VALIDATION;

		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_global_afi_safi_ip_unicast_vpn_config_nexthop_modify(
			args);
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_nexthop_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_global_afi_safi_ip_unicast_vpn_config_nexthop_destroy(
			args);
	}

	return NB_OK;
}

static int bgp_global_afi_safi_ip_unicast_vpn_config_import_export_vpn_modify(
	struct nb_cb_modify_args *args, const char *direction_str,
	bool is_enable)
{
	struct bgp *bgp;
	const struct lyd_node *af_dnode;
	const char *af_name;
	afi_t afi;
	safi_t safi;
	int previous_state;
	int flag;
	vpn_policy_direction_t dir;

	af_dnode = yang_dnode_get_parent(args->dnode, "afi-safi");
	af_name = yang_dnode_get_string(af_dnode, "./afi-safi-name");
	yang_afi_safi_identity2value(af_name, &afi, &safi);
	bgp = nb_running_get_entry(af_dnode, NULL, true);

	if (!strcmp(direction_str, "import")) {
		flag = BGP_CONFIG_MPLSVPN_TO_VRF_IMPORT;
		dir = BGP_VPN_POLICY_DIR_FROMVPN;
	} else if (!strcmp(direction_str, "export")) {
		flag = BGP_CONFIG_VRF_TO_MPLSVPN_EXPORT;
		dir = BGP_VPN_POLICY_DIR_TOVPN;
	} else {
		snprintf(args->errmsg, args->errmsg_len,
			 "unknown direction %s\n", direction_str);
		return NB_ERR_INCONSISTENCY;
	}

	previous_state = CHECK_FLAG(bgp->af_flags[afi][safi], flag);

	if (is_enable) {
		SET_FLAG(bgp->af_flags[afi][safi], flag);
		if (!previous_state) {
			/* trigger export current vrf */
			vpn_leak_postchange(dir, afi, bgp_get_default(), bgp);
		}
	} else {
		if (previous_state) {
			/* trigger un-export current vrf */
			vpn_leak_prechange(dir, afi, bgp_get_default(), bgp);
		}
		UNSET_FLAG(bgp->af_flags[afi][safi], flag);
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/import-vpn
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_import_vpn_modify(
	struct nb_cb_modify_args *args)
{
	bool is_enable = false;
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
		bgp = nb_running_get_entry(args->dnode, NULL, false);
		if (!bgp)
			return NB_OK;

		if (BGP_INSTANCE_TYPE_VRF != bgp->inst_type
		    && BGP_INSTANCE_TYPE_DEFAULT != bgp->inst_type) {
			snprintf(
				args->errmsg, args->errmsg_len,
				"import|export vpn valid only for bgp vrf or default instance");
			return NB_ERR_VALIDATION;
		}

		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		if (yang_dnode_get_bool(args->dnode, NULL))
			is_enable = true;

		return bgp_global_afi_safi_ip_unicast_vpn_config_import_export_vpn_modify(
			args, "import", is_enable);
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/export-vpn
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_export_vpn_modify(
	struct nb_cb_modify_args *args)
{
	bool is_enable = false;
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
		bgp = nb_running_get_entry(args->dnode, NULL, false);
		if (!bgp)
			return NB_OK;

		if (BGP_INSTANCE_TYPE_VRF != bgp->inst_type
		    && BGP_INSTANCE_TYPE_DEFAULT != bgp->inst_type) {
			snprintf(
				args->errmsg, args->errmsg_len,
				"import|export vpn valid only for bgp vrf or default instance");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		if (yang_dnode_get_bool(args->dnode, NULL))
			is_enable = true;

		return bgp_global_afi_safi_ip_unicast_vpn_config_import_export_vpn_modify(
			args, "export", is_enable);
	}

	return NB_OK;
}


static int bgp_global_afi_safi_ip_unicast_vpn_config_import_vrfs_create(
	struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	const struct lyd_node *af_dnode;
	const char *af_name;
	afi_t afi;
	safi_t safi;
	int ret = 0;
	as_t as;
	struct bgp *vrf_bgp, *bgp_default;
	const char *import_name;
	char *vname;
	enum bgp_instance_type bgp_type = BGP_INSTANCE_TYPE_VRF;
	struct listnode *node;

	af_dnode = yang_dnode_get_parent(args->dnode, "afi-safi");
	af_name = yang_dnode_get_string(af_dnode, "./afi-safi-name");
	yang_afi_safi_identity2value(af_name, &afi, &safi);
	bgp = nb_running_get_entry(af_dnode, NULL, true);

	as = bgp->as;
	import_name = yang_dnode_get_string(args->dnode, "./vrf");

	if (((BGP_INSTANCE_TYPE_DEFAULT == bgp->inst_type)
	     && (strcmp(import_name, VRF_DEFAULT_NAME) == 0))
	    || (bgp->name && (strcmp(import_name, bgp->name) == 0))) {
		snprintf(args->errmsg, args->errmsg_len,
			 "Cannot %s vrf %s into itself\n", "import",
			 import_name);
		return NB_ERR_INCONSISTENCY;
	}

	bgp_default = bgp_get_default();
	if (!bgp_default) {
		/* Auto-create assuming the same AS */
		ret = bgp_get_vty(&bgp_default, &as, NULL,
				  BGP_INSTANCE_TYPE_DEFAULT);

		if (ret) {
			snprintf(
				args->errmsg, args->errmsg_len,
				"VRF default is not configured as a bgp instance");
			return NB_ERR_INCONSISTENCY;
		}
	}

	vrf_bgp = bgp_lookup_by_name(import_name);
	if (!vrf_bgp) {
		if (strcmp(import_name, VRF_DEFAULT_NAME) == 0)
			vrf_bgp = bgp_default;
		else
			/* Auto-create assuming the same AS */
			ret = bgp_get_vty(&vrf_bgp, &as, import_name, bgp_type);

		if (ret) {
			snprintf(args->errmsg, args->errmsg_len,
				 "VRF %s is not configured as a bgp instance\n",
				 import_name);
			return NB_ERR_INCONSISTENCY;
		}
	}

	/* Already importing from "import_vrf"? */
	for (ALL_LIST_ELEMENTS_RO(bgp->vpn_policy[afi].import_vrf, node,
				  vname)) {
		if (strcmp(vname, import_name) == 0) {
			snprintf(args->errmsg, args->errmsg_len,
				 "already importing from vrf %s", import_name);
			return NB_ERR_INCONSISTENCY;
		}
	}

	vrf_import_from_vrf(bgp, vrf_bgp, afi, safi);

	return NB_OK;
}


static int bgp_global_afi_safi_ip_unicast_vpn_config_import_vrf_list_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const struct lyd_node *af_dnode;
	const char *af_name;
	afi_t afi;
	safi_t safi;
	int ret = 0;
	as_t as;
	struct bgp *vrf_bgp, *bgp_default;
	const char *import_name;
	enum bgp_instance_type bgp_type = BGP_INSTANCE_TYPE_VRF;

	af_dnode = yang_dnode_get_parent(args->dnode, "afi-safi");
	af_name = yang_dnode_get_string(af_dnode, "./afi-safi-name");
	yang_afi_safi_identity2value(af_name, &afi, &safi);
	bgp = nb_running_get_entry(af_dnode, NULL, true);

	as = bgp->as;
	import_name = yang_dnode_get_string(args->dnode, "./vrf");

	if (((BGP_INSTANCE_TYPE_DEFAULT == bgp->inst_type)
	     && (strcmp(import_name, VRF_DEFAULT_NAME) == 0))
	    || (bgp->name && (strcmp(import_name, bgp->name) == 0))) {
		snprintf(args->errmsg, args->errmsg_len,
			 "Cannot %s vrf %s into itself\n", "unimport",
			 import_name);
		return NB_ERR_INCONSISTENCY;
	}

	bgp_default = bgp_get_default();
	if (!bgp_default) {
		/* Auto-create assuming the same AS */
		ret = bgp_get_vty(&bgp_default, &as, NULL,
				  BGP_INSTANCE_TYPE_DEFAULT);

		if (ret) {
			snprintf(
				args->errmsg, args->errmsg_len, "%s",
				"VRF default is not configured as a bgp instance");
			return NB_ERR_INCONSISTENCY;
		}
	}

	vrf_bgp = bgp_lookup_by_name(import_name);
	if (!vrf_bgp) {
		if (strcmp(import_name, VRF_DEFAULT_NAME) == 0)
			vrf_bgp = bgp_default;
		else
			/* Auto-create assuming the same AS */
			ret = bgp_get_vty(&vrf_bgp, &as, import_name, bgp_type);

		if (ret) {
			snprintf(args->errmsg, args->errmsg_len,
				 "VRF %s is not configured as a bgp instance\n",
				 import_name);
			return NB_ERR_INCONSISTENCY;
		}
	}

	vrf_unimport_from_vrf(bgp, vrf_bgp, afi, safi);

	return NB_OK;
}


/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/import-vrf-list
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_import_vrf_list_create(
	struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	const struct lyd_node *af_dnode;
	const char *af_name;
	afi_t afi;
	safi_t safi;

	switch (args->event) {
	case NB_EV_VALIDATE:
		bgp = nb_running_get_entry(args->dnode, NULL, false);
		if (!bgp)
			return NB_OK;
		af_dnode = yang_dnode_get_parent(args->dnode, "afi-safi");
		af_name = yang_dnode_get_string(af_dnode, "./afi-safi-name");
		yang_afi_safi_identity2value(af_name, &afi, &safi);

		if (!vpn_policy_check_import(bgp, afi, safi, true, args->errmsg,
					     args->errmsg_len))
			return NB_ERR_VALIDATION;

		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_global_afi_safi_ip_unicast_vpn_config_import_vrfs_create(
			args);
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_import_vrf_list_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_global_afi_safi_ip_unicast_vpn_config_import_vrf_list_destroy(
			args);
	}

	return NB_OK;
}

static int bgp_global_afi_safi_ip_unicast_vpn_config_rmap_import_modify(
	struct nb_cb_modify_args *args, const char *dstr)
{
	struct bgp *bgp;
	const struct lyd_node *af_dnode;
	const char *af_name;
	afi_t afi;
	safi_t safi;
	const char *rmap_str = NULL;
	int dodir[BGP_VPN_POLICY_DIR_MAX] = {0};
	vpn_policy_direction_t dir;

	af_dnode = yang_dnode_get_parent(args->dnode, "afi-safi");
	af_name = yang_dnode_get_string(af_dnode, "./afi-safi-name");
	yang_afi_safi_identity2value(af_name, &afi, &safi);
	bgp = nb_running_get_entry(af_dnode, NULL, true);

	if (!strcmp(dstr, "import")) {
		rmap_str = yang_dnode_get_string(args->dnode, NULL);
		dodir[BGP_VPN_POLICY_DIR_FROMVPN] = 1;
	} else if (!strcmp(dstr, "export")) {
		rmap_str = yang_dnode_get_string(args->dnode, NULL);
		dodir[BGP_VPN_POLICY_DIR_TOVPN] = 1;
	} else if (!strcmp(dstr, "both")) {
		dodir[BGP_VPN_POLICY_DIR_FROMVPN] = 1;
		dodir[BGP_VPN_POLICY_DIR_TOVPN] = 1;
	}

	for (dir = 0; dir < BGP_VPN_POLICY_DIR_MAX; ++dir) {
		if (!dodir[dir])
			continue;

		vpn_leak_prechange(dir, afi, bgp_get_default(), bgp);

		if (bgp->vpn_policy[afi].rmap_name[dir])
			XFREE(MTYPE_ROUTE_MAP_NAME,
			      bgp->vpn_policy[afi].rmap_name[dir]);
		bgp->vpn_policy[afi].rmap_name[dir] =
			XSTRDUP(MTYPE_ROUTE_MAP_NAME, rmap_str);
		bgp->vpn_policy[afi].rmap[dir] =
			route_map_lookup_by_name(rmap_str);
		if (!bgp->vpn_policy[afi].rmap[dir])
			return NB_OK;


		vpn_leak_postchange(dir, afi, bgp_get_default(), bgp);
	}

	return NB_OK;
}

static int bgp_global_afi_safi_ip_unicast_vpn_config_rmap_import_destroy(
	struct nb_cb_destroy_args *args, const char *dstr)
{
	struct bgp *bgp;
	const struct lyd_node *af_dnode;
	const char *af_name;
	afi_t afi;
	safi_t safi;
	int dodir[BGP_VPN_POLICY_DIR_MAX] = {0};
	vpn_policy_direction_t dir;

	af_dnode = yang_dnode_get_parent(args->dnode, "afi-safi");
	af_name = yang_dnode_get_string(af_dnode, "./afi-safi-name");
	yang_afi_safi_identity2value(af_name, &afi, &safi);
	bgp = nb_running_get_entry(af_dnode, NULL, true);

	if (!strcmp(dstr, "import")) {
		dodir[BGP_VPN_POLICY_DIR_FROMVPN] = 1;
	} else if (!strcmp(dstr, "export")) {
		dodir[BGP_VPN_POLICY_DIR_TOVPN] = 1;
	} else if (!strcmp(dstr, "both")) {
		dodir[BGP_VPN_POLICY_DIR_FROMVPN] = 1;
		dodir[BGP_VPN_POLICY_DIR_TOVPN] = 1;
	}

	for (dir = 0; dir < BGP_VPN_POLICY_DIR_MAX; ++dir) {
		if (!dodir[dir])
			continue;

		vpn_leak_prechange(dir, afi, bgp_get_default(), bgp);

		if (bgp->vpn_policy[afi].rmap_name[dir])
			XFREE(MTYPE_ROUTE_MAP_NAME,
			      bgp->vpn_policy[afi].rmap_name[dir]);
		bgp->vpn_policy[afi].rmap_name[dir] = NULL;
		bgp->vpn_policy[afi].rmap[dir] = NULL;

		vpn_leak_postchange(dir, afi, bgp_get_default(), bgp);
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/rmap-import
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_rmap_import_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const struct lyd_node *af_dnode;
	const char *af_name;
	afi_t afi;
	safi_t safi;

	switch (args->event) {
	case NB_EV_VALIDATE:
		bgp = nb_running_get_entry(args->dnode, NULL, false);
		if (!bgp)
			return NB_OK;
		af_dnode = yang_dnode_get_parent(args->dnode, "afi-safi");
		af_name = yang_dnode_get_string(af_dnode, "./afi-safi-name");
		yang_afi_safi_identity2value(af_name, &afi, &safi);

		if (!vpn_policy_check_import(bgp, afi, safi, false,
					     args->errmsg, args->errmsg_len))
			return NB_ERR_VALIDATION;
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_global_afi_safi_ip_unicast_vpn_config_rmap_import_modify(
			args, "import");
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_rmap_import_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const struct lyd_node *af_dnode;
	const char *af_name;
	afi_t afi;
	safi_t safi;

	switch (args->event) {
	case NB_EV_VALIDATE:
		bgp = nb_running_get_entry(args->dnode, NULL, false);
		if (!bgp)
			return NB_OK;
		af_dnode = yang_dnode_get_parent(args->dnode, "afi-safi");
		af_name = yang_dnode_get_string(af_dnode, "./afi-safi-name");
		yang_afi_safi_identity2value(af_name, &afi, &safi);

		if (!vpn_policy_check_import(bgp, afi, safi, false,
					     args->errmsg, args->errmsg_len))
			return NB_ERR_VALIDATION;
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_global_afi_safi_ip_unicast_vpn_config_rmap_import_destroy(
			args, "import");
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/rmap-export
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_rmap_export_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_global_afi_safi_ip_unicast_vpn_config_rmap_import_modify(
			args, "export");
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_rmap_export_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_global_afi_safi_ip_unicast_vpn_config_rmap_import_destroy(
			args, "export");
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/redirect-rt
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_redirect_rt_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_redirect_rt_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/import-rt-list
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_import_rt_list_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_import_rt_list_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/export-rt-list
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_export_rt_list_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_export_rt_list_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/rt-list
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_rt_list_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_rt_list_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/network-config
 */
int bgp_global_afi_safis_afi_safi_ipv6_unicast_network_config_create(
	struct nb_cb_create_args *args)
{
	/* Handled in network_config_apply_finish callback */

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv6_unicast_network_config_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_global_afi_safis_afi_safi_network_config_destroy(
			args);
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/network-config/backdoor
 */
int bgp_global_afi_safis_afi_safi_ipv6_unicast_network_config_backdoor_modify(
	struct nb_cb_modify_args *args)
{
	/* Handled in unicast_network_config_apply_finish callback */

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/network-config/label-index
 */
int bgp_global_afi_safis_afi_safi_ipv6_unicast_network_config_label_index_modify(
	struct nb_cb_modify_args *args)
{
	/* Handled in unicast_network_config_apply_finish callback */

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv6_unicast_network_config_label_index_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/network-config/rmap-policy-export
 */
int bgp_global_afi_safis_afi_safi_ipv6_unicast_network_config_rmap_policy_export_modify(
	struct nb_cb_modify_args *args)
{
	/* Handled in unicast_network_config_apply_finish callback */

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv6_unicast_network_config_rmap_policy_export_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/aggregate-route
 */
int bgp_global_afi_safis_afi_safi_ipv6_unicast_aggregate_route_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv6_unicast_aggregate_route_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_global_afi_safi_aggregate_route_destroy(args);
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/aggregate-route/as-set
 */
int bgp_global_afi_safis_afi_safi_ipv6_unicast_aggregate_route_as_set_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/aggregate-route/summary-only
 */
int bgp_global_afi_safis_afi_safi_ipv6_unicast_aggregate_route_summary_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/aggregate-route/rmap-policy-export
 */
int bgp_global_afi_safis_afi_safi_ipv6_unicast_aggregate_route_rmap_policy_export_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv6_unicast_aggregate_route_rmap_policy_export_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/aggregate-route/origin
 */
int bgp_global_afi_safis_afi_safi_ipv6_unicast_aggregate_route_origin_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/aggregate-route/match-med
 */
int bgp_global_afi_safis_afi_safi_ipv6_unicast_aggregate_route_match_med_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/aggregate-route/suppress-map
 */
int bgp_global_afi_safis_afi_safi_ipv6_unicast_aggregate_route_suppress_map_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv6_unicast_aggregate_route_suppress_map_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/admin-distance-route
 */
int bgp_global_afi_safis_afi_safi_ipv6_unicast_admin_distance_route_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv6_unicast_admin_distance_route_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_global_afi_safi_admin_distance_route_destroy(args);
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/admin-distance-route/distance
 */
int bgp_global_afi_safis_afi_safi_ipv6_unicast_admin_distance_route_distance_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/admin-distance-route/access-list-policy-export
 */
int bgp_global_afi_safis_afi_safi_ipv6_unicast_admin_distance_route_access_list_policy_export_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv6_unicast_admin_distance_route_access_list_policy_export_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/route-flap-dampening/enable
 */
int bgp_global_afi_safis_afi_safi_ipv6_unicast_route_flap_dampening_enable_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		return bgp_global_afi_safi_route_flap_validation(args);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/route-flap-dampening/reach-decay
 */
int bgp_global_afi_safis_afi_safi_ipv6_unicast_route_flap_dampening_reach_decay_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv6_unicast_route_flap_dampening_reach_decay_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/route-flap-dampening/reuse-above
 */
int bgp_global_afi_safis_afi_safi_ipv6_unicast_route_flap_dampening_reuse_above_modify(
	struct nb_cb_modify_args *args)
{
	int reuse = DEFAULT_REUSE;
	int suppress = DEFAULT_SUPPRESS;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (yang_dnode_exists(args->dnode, "../suppress-above"))
			suppress = yang_dnode_get_uint16(args->dnode,
							 "../suppress-above");
		reuse = yang_dnode_get_uint16(args->dnode, "../reuse-above");
		if (suppress < reuse) {
			snprintf(
				args->errmsg, args->errmsg_len,
				"Suppress value cannot be less than reuse value \n");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv6_unicast_route_flap_dampening_reuse_above_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/route-flap-dampening/suppress-above
 */
int bgp_global_afi_safis_afi_safi_ipv6_unicast_route_flap_dampening_suppress_above_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv6_unicast_route_flap_dampening_suppress_above_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/route-flap-dampening/unreach-decay
 */
int bgp_global_afi_safis_afi_safi_ipv6_unicast_route_flap_dampening_unreach_decay_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv6_unicast_route_flap_dampening_unreach_decay_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/use-multiple-paths/ebgp/maximum-paths
 */
int bgp_global_afi_safis_afi_safi_ipv6_unicast_use_multiple_paths_ebgp_maximum_paths_modify(
	struct nb_cb_modify_args *args)
{
	uint16_t maxpaths;

	switch (args->event) {
	case NB_EV_VALIDATE:
		maxpaths = yang_dnode_get_uint16(args->dnode, NULL);
		if (maxpaths > multipath_num) {
			snprintf(args->errmsg, args->errmsg_len,
				 "maxpaths %u is out of range %u", maxpaths,
				 multipath_num);
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_global_afi_safi_ip_unicast_use_multiple_paths_ebgp_maximum_paths_modify(
			args);
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/use-multiple-paths/ibgp/maximum-paths
 */
int bgp_global_afi_safis_afi_safi_ipv6_unicast_use_multiple_paths_ibgp_maximum_paths_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/use-multiple-paths/ibgp/cluster-length-list
 */
int bgp_global_afi_safis_afi_safi_ipv6_unicast_use_multiple_paths_ibgp_cluster_length_list_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv6_unicast_use_multiple_paths_ibgp_cluster_length_list_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/redistribution-list
 */
int bgp_global_afi_safis_afi_safi_ipv6_unicast_redistribution_list_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv6_unicast_redistribution_list_destroy(
	struct nb_cb_destroy_args *args)
{
	const struct lyd_node *af_dnode;
	struct bgp *bgp;
	const char *af_name;
	afi_t afi;
	safi_t safi;
	int route_type;
	int route_instance;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		af_dnode = yang_dnode_get_parent(args->dnode, "afi-safi");
		af_name = yang_dnode_get_string(af_dnode, "./afi-safi-name");
		yang_afi_safi_identity2value(af_name, &afi, &safi);
		bgp = nb_running_get_entry(af_dnode, NULL, true);

		route_type = yang_dnode_get_enum(args->dnode, "./route-type");
		route_instance =
			yang_dnode_get_uint16(args->dnode, "./route-instance");

		bgp_redistribute_unset(bgp, afi, route_type, route_instance);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/redistribution-list/metric
 */
int bgp_global_afi_safis_afi_safi_ipv6_unicast_redistribution_list_metric_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv6_unicast_redistribution_list_metric_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/redistribution-list/rmap-policy-import
 */
int bgp_global_afi_safis_afi_safi_ipv6_unicast_redistribution_list_rmap_policy_import_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv6_unicast_redistribution_list_rmap_policy_import_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/admin-distance
 */
void bgp_global_afi_safis_afi_safi_ipv6_unicast_admin_distance_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	bgp_global_afi_safis_admin_distance_modify(args);
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/admin-distance/external
 */
int bgp_global_afi_safis_afi_safi_ipv6_unicast_admin_distance_external_modify(
	struct nb_cb_modify_args *args)
{
	/* Handled in admin_distance_apply_finish callback */

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/admin-distance/internal
 */
int bgp_global_afi_safis_afi_safi_ipv6_unicast_admin_distance_internal_modify(
	struct nb_cb_modify_args *args)
{
	/* Handled in admin_distance_apply_finish callback */

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/admin-distance/local
 */
int bgp_global_afi_safis_afi_safi_ipv6_unicast_admin_distance_local_modify(
	struct nb_cb_modify_args *args)
{
	/* Handled in admin_distance_apply_finish callback */

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/filter-config/rmap-export
 */
int bgp_global_afi_safis_afi_safi_ipv6_unicast_filter_config_rmap_export_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv6_unicast_filter_config_rmap_export_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/rd
 */
int bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_rd_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const struct lyd_node *af_dnode;
	const char *af_name;
	afi_t afi;
	safi_t safi;

	switch (args->event) {
	case NB_EV_VALIDATE:
		bgp = nb_running_get_entry(args->dnode, NULL, false);
		if (!bgp)
			return NB_OK;

		af_dnode = yang_dnode_get_parent(args->dnode, "afi-safi");
		af_name = yang_dnode_get_string(af_dnode, "./afi-safi-name");
		yang_afi_safi_identity2value(af_name, &afi, &safi);

		if (!vpn_policy_check_import(bgp, afi, safi, false,
					     args->errmsg, args->errmsg_len))
			return NB_ERR_VALIDATION;

		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_global_afi_safi_ip_unicast_vpn_config_rd_modify(
			args);
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_rd_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_global_afi_safi_ip_unicast_vpn_config_rd_destroy(
			args);
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/label
 */
int bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_label_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_label_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/label-auto
 */
int bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_label_auto_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_label_auto_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/nexthop
 */
int bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_nexthop_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const struct lyd_node *af_dnode;
	const char *af_name;
	afi_t afi;
	safi_t safi;

	switch (args->event) {
	case NB_EV_VALIDATE:
		bgp = nb_running_get_entry(args->dnode, NULL, false);
		if (!bgp)
			return NB_OK;

		af_dnode = yang_dnode_get_parent(args->dnode, "afi-safi");
		af_name = yang_dnode_get_string(af_dnode, "./afi-safi-name");
		yang_afi_safi_identity2value(af_name, &afi, &safi);

		if (!vpn_policy_check_import(bgp, afi, safi, false,
					     args->errmsg, args->errmsg_len))
			return NB_ERR_VALIDATION;

		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_global_afi_safi_ip_unicast_vpn_config_nexthop_modify(
			args);
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_nexthop_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_global_afi_safi_ip_unicast_vpn_config_nexthop_destroy(
			args);
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/import-vpn
 */
int bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_import_vpn_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/export-vpn
 */
int bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_export_vpn_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/import-vrf-list
 */
int bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_import_vrf_list_create(
	struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	const struct lyd_node *af_dnode;
	const char *af_name;
	afi_t afi;
	safi_t safi;

	switch (args->event) {
	case NB_EV_VALIDATE:
		bgp = nb_running_get_entry(args->dnode, NULL, false);
		if (!bgp)
			return NB_OK;
		af_dnode = yang_dnode_get_parent(args->dnode, "afi-safi");
		af_name = yang_dnode_get_string(af_dnode, "./afi-safi-name");
		yang_afi_safi_identity2value(af_name, &afi, &safi);

		if (!vpn_policy_check_import(bgp, afi, safi, true, args->errmsg,
					     args->errmsg_len))
			return NB_ERR_VALIDATION;

		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_global_afi_safi_ip_unicast_vpn_config_import_vrfs_create(
			args);
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_import_vrf_list_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_global_afi_safi_ip_unicast_vpn_config_import_vrf_list_destroy(
			args);
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/rmap-import
 */
int bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_rmap_import_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_global_afi_safi_ip_unicast_vpn_config_rmap_import_modify(
			args, "import");
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_rmap_import_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_global_afi_safi_ip_unicast_vpn_config_rmap_import_destroy(
			args, "import");
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/rmap-export
 */
int bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_rmap_export_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_global_afi_safi_ip_unicast_vpn_config_rmap_import_modify(
			args, "export");
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_rmap_export_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_global_afi_safi_ip_unicast_vpn_config_rmap_import_destroy(
			args, "export");
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/redirect-rt
 */
int bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_redirect_rt_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_redirect_rt_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/import-rt-list
 */
int bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_import_rt_list_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_import_rt_list_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/export-rt-list
 */
int bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_export_rt_list_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_export_rt_list_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/vpn-config/rt-list
 */
int bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_rt_list_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv6_unicast_vpn_config_rt_list_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-labeled-unicast/use-multiple-paths/ebgp/maximum-paths
 */
int bgp_global_afi_safis_afi_safi_ipv4_labeled_unicast_use_multiple_paths_ebgp_maximum_paths_modify(
	struct nb_cb_modify_args *args)
{
	uint16_t maxpaths;

	switch (args->event) {
	case NB_EV_VALIDATE:
		maxpaths = yang_dnode_get_uint16(args->dnode, NULL);
		if (maxpaths > multipath_num) {
			snprintf(args->errmsg, args->errmsg_len,
				 "maxpaths %u is out of range %u", maxpaths,
				 multipath_num);
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_global_afi_safi_ip_unicast_use_multiple_paths_ebgp_maximum_paths_modify(
			args);
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-labeled-unicast/use-multiple-paths/ibgp/maximum-paths
 */
int bgp_global_afi_safis_afi_safi_ipv4_labeled_unicast_use_multiple_paths_ibgp_maximum_paths_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-labeled-unicast/use-multiple-paths/ibgp/cluster-length-list
 */
int bgp_global_afi_safis_afi_safi_ipv4_labeled_unicast_use_multiple_paths_ibgp_cluster_length_list_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_labeled_unicast_use_multiple_paths_ibgp_cluster_length_list_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-labeled-unicast/route-flap-dampening/enable
 */
int bgp_global_afi_safis_afi_safi_ipv4_labeled_unicast_route_flap_dampening_enable_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		return bgp_global_afi_safi_route_flap_validation(args);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-labeled-unicast/route-flap-dampening/reach-decay
 */
int bgp_global_afi_safis_afi_safi_ipv4_labeled_unicast_route_flap_dampening_reach_decay_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_labeled_unicast_route_flap_dampening_reach_decay_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-labeled-unicast/route-flap-dampening/reuse-above
 */
int bgp_global_afi_safis_afi_safi_ipv4_labeled_unicast_route_flap_dampening_reuse_above_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_labeled_unicast_route_flap_dampening_reuse_above_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-labeled-unicast/route-flap-dampening/suppress-above
 */
int bgp_global_afi_safis_afi_safi_ipv4_labeled_unicast_route_flap_dampening_suppress_above_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_labeled_unicast_route_flap_dampening_suppress_above_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-labeled-unicast/route-flap-dampening/unreach-decay
 */
int bgp_global_afi_safis_afi_safi_ipv4_labeled_unicast_route_flap_dampening_unreach_decay_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_labeled_unicast_route_flap_dampening_unreach_decay_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/use-multiple-paths/ebgp/maximum-paths
 */
int bgp_global_afi_safis_afi_safi_ipv6_labeled_unicast_use_multiple_paths_ebgp_maximum_paths_modify(
	struct nb_cb_modify_args *args)
{
	uint16_t maxpaths;

	switch (args->event) {
	case NB_EV_VALIDATE:
		maxpaths = yang_dnode_get_uint16(args->dnode, NULL);
		if (maxpaths > multipath_num) {
			snprintf(args->errmsg, args->errmsg_len,
				 "maxpaths %u is out of range %u", maxpaths,
				 multipath_num);
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_global_afi_safi_ip_unicast_use_multiple_paths_ebgp_maximum_paths_modify(
			args);
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/use-multiple-paths/ibgp/maximum-paths
 */
int bgp_global_afi_safis_afi_safi_ipv6_labeled_unicast_use_multiple_paths_ibgp_maximum_paths_modify(
	struct nb_cb_modify_args *args)
{
	uint16_t maxpaths;

	switch (args->event) {
	case NB_EV_VALIDATE:
		maxpaths = yang_dnode_get_uint16(args->dnode, NULL);
		if (maxpaths > multipath_num) {
			snprintf(args->errmsg, args->errmsg_len,
				 "maxpaths %u is out of range %u", maxpaths,
				 multipath_num);
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/use-multiple-paths/ibgp/cluster-length-list
 */
int bgp_global_afi_safis_afi_safi_ipv6_labeled_unicast_use_multiple_paths_ibgp_cluster_length_list_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv6_labeled_unicast_use_multiple_paths_ibgp_cluster_length_list_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/route-flap-dampening/enable
 */
int bgp_global_afi_safis_afi_safi_ipv6_labeled_unicast_route_flap_dampening_enable_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		return bgp_global_afi_safi_route_flap_validation(args);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/route-flap-dampening/reach-decay
 */
int bgp_global_afi_safis_afi_safi_ipv6_labeled_unicast_route_flap_dampening_reach_decay_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv6_labeled_unicast_route_flap_dampening_reach_decay_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/route-flap-dampening/reuse-above
 */
int bgp_global_afi_safis_afi_safi_ipv6_labeled_unicast_route_flap_dampening_reuse_above_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv6_labeled_unicast_route_flap_dampening_reuse_above_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/route-flap-dampening/suppress-above
 */
int bgp_global_afi_safis_afi_safi_ipv6_labeled_unicast_route_flap_dampening_suppress_above_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv6_labeled_unicast_route_flap_dampening_suppress_above_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/route-flap-dampening/unreach-decay
 */
int bgp_global_afi_safis_afi_safi_ipv6_labeled_unicast_route_flap_dampening_unreach_decay_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv6_labeled_unicast_route_flap_dampening_unreach_decay_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/network-config
 */
int bgp_global_afi_safis_afi_safi_ipv4_multicast_network_config_create(
	struct nb_cb_create_args *args)
{
	/* Handled in network_config_apply_finish callback */

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_multicast_network_config_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_global_afi_safis_afi_safi_network_config_destroy(
			args);
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/network-config/backdoor
 */
int bgp_global_afi_safis_afi_safi_ipv4_multicast_network_config_backdoor_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/network-config/label-index
 */
int bgp_global_afi_safis_afi_safi_ipv4_multicast_network_config_label_index_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_multicast_network_config_label_index_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/network-config/rmap-policy-export
 */
int bgp_global_afi_safis_afi_safi_ipv4_multicast_network_config_rmap_policy_export_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_multicast_network_config_rmap_policy_export_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/aggregate-route
 */
int bgp_global_afi_safis_afi_safi_ipv4_multicast_aggregate_route_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_multicast_aggregate_route_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/aggregate-route/as-set
 */
int bgp_global_afi_safis_afi_safi_ipv4_multicast_aggregate_route_as_set_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/aggregate-route/summary-only
 */
int bgp_global_afi_safis_afi_safi_ipv4_multicast_aggregate_route_summary_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/aggregate-route/rmap-policy-export
 */
int bgp_global_afi_safis_afi_safi_ipv4_multicast_aggregate_route_rmap_policy_export_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_multicast_aggregate_route_rmap_policy_export_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/aggregate-route/origin
 */
int bgp_global_afi_safis_afi_safi_ipv4_multicast_aggregate_route_origin_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/aggregate-route/match-med
 */
int bgp_global_afi_safis_afi_safi_ipv4_multicast_aggregate_route_match_med_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/aggregate-route/suppress-map
 */
int bgp_global_afi_safis_afi_safi_ipv4_multicast_aggregate_route_suppress_map_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_multicast_aggregate_route_suppress_map_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/admin-distance-route
 */
int bgp_global_afi_safis_afi_safi_ipv4_multicast_admin_distance_route_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_multicast_admin_distance_route_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_global_afi_safi_admin_distance_route_destroy(args);
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/admin-distance-route/distance
 */
int bgp_global_afi_safis_afi_safi_ipv4_multicast_admin_distance_route_distance_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/admin-distance-route/access-list-policy-export
 */
int bgp_global_afi_safis_afi_safi_ipv4_multicast_admin_distance_route_access_list_policy_export_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_multicast_admin_distance_route_access_list_policy_export_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/admin-distance-route/distance
 */
int bgp_global_afi_safis_afi_safi_ipv6_multicast_admin_distance_route_distance_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/admin-distance-route/access-list-policy-export
 */
int bgp_global_afi_safis_afi_safi_ipv6_multicast_admin_distance_route_access_list_policy_export_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv6_multicast_admin_distance_route_access_list_policy_export_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/route-flap-dampening/enable
 */
int bgp_global_afi_safis_afi_safi_ipv6_multicast_route_flap_dampening_enable_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		return bgp_global_afi_safi_route_flap_validation(args);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/route-flap-dampening/reach-decay
 */
int bgp_global_afi_safis_afi_safi_ipv6_multicast_route_flap_dampening_reach_decay_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv6_multicast_route_flap_dampening_reach_decay_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/route-flap-dampening/reuse-above
 */
int bgp_global_afi_safis_afi_safi_ipv6_multicast_route_flap_dampening_reuse_above_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv6_multicast_route_flap_dampening_reuse_above_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/route-flap-dampening/suppress-above
 */
int bgp_global_afi_safis_afi_safi_ipv6_multicast_route_flap_dampening_suppress_above_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv6_multicast_route_flap_dampening_suppress_above_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/route-flap-dampening/unreach-decay
 */
int bgp_global_afi_safis_afi_safi_ipv6_multicast_route_flap_dampening_unreach_decay_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv6_multicast_route_flap_dampening_unreach_decay_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/admin-distance
 */
void bgp_global_afi_safis_afi_safi_ipv4_multicast_admin_distance_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	bgp_global_afi_safis_admin_distance_modify(args);
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/admin-distance/external
 */
int bgp_global_afi_safis_afi_safi_ipv4_multicast_admin_distance_external_modify(
	struct nb_cb_modify_args *args)
{
	/* Handled in admin_distance_apply_finish callback */

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/admin-distance/internal
 */
int bgp_global_afi_safis_afi_safi_ipv4_multicast_admin_distance_internal_modify(
	struct nb_cb_modify_args *args)
{
	/* Handled in admin_distance_apply_finish callback */

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/admin-distance/local
 */
int bgp_global_afi_safis_afi_safi_ipv4_multicast_admin_distance_local_modify(
	struct nb_cb_modify_args *args)
{
	/* Handled in admin_distance_apply_finish callback */

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/route-flap-dampening/enable
 */
int bgp_global_afi_safis_afi_safi_ipv4_multicast_route_flap_dampening_enable_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		return bgp_global_afi_safi_route_flap_validation(args);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/route-flap-dampening/reach-decay
 */
int bgp_global_afi_safis_afi_safi_ipv4_multicast_route_flap_dampening_reach_decay_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_multicast_route_flap_dampening_reach_decay_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/route-flap-dampening/reuse-above
 */
int bgp_global_afi_safis_afi_safi_ipv4_multicast_route_flap_dampening_reuse_above_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_multicast_route_flap_dampening_reuse_above_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/route-flap-dampening/suppress-above
 */
int bgp_global_afi_safis_afi_safi_ipv4_multicast_route_flap_dampening_suppress_above_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_multicast_route_flap_dampening_suppress_above_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/route-flap-dampening/unreach-decay
 */
int bgp_global_afi_safis_afi_safi_ipv4_multicast_route_flap_dampening_unreach_decay_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_multicast_route_flap_dampening_unreach_decay_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/filter-config/rmap-export
 */
int bgp_global_afi_safis_afi_safi_ipv4_multicast_filter_config_rmap_export_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_multicast_filter_config_rmap_export_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/network-config
 */
int bgp_global_afi_safis_afi_safi_ipv6_multicast_network_config_create(
	struct nb_cb_create_args *args)
{
	/* Handled in network_config_apply_finish callback */

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv6_multicast_network_config_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_global_afi_safis_afi_safi_network_config_destroy(
			args);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/network-config/backdoor
 */
int bgp_global_afi_safis_afi_safi_ipv6_multicast_network_config_backdoor_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/network-config/label-index
 */
int bgp_global_afi_safis_afi_safi_ipv6_multicast_network_config_label_index_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv6_multicast_network_config_label_index_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/network-config/rmap-policy-export
 */
int bgp_global_afi_safis_afi_safi_ipv6_multicast_network_config_rmap_policy_export_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv6_multicast_network_config_rmap_policy_export_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/aggregate-route
 */
int bgp_global_afi_safis_afi_safi_ipv6_multicast_aggregate_route_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv6_multicast_aggregate_route_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/aggregate-route/as-set
 */
int bgp_global_afi_safis_afi_safi_ipv6_multicast_aggregate_route_as_set_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/aggregate-route/summary-only
 */
int bgp_global_afi_safis_afi_safi_ipv6_multicast_aggregate_route_summary_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/aggregate-route/rmap-policy-export
 */
int bgp_global_afi_safis_afi_safi_ipv6_multicast_aggregate_route_rmap_policy_export_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv6_multicast_aggregate_route_rmap_policy_export_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/aggregate-route/origin
 */
int bgp_global_afi_safis_afi_safi_ipv6_multicast_aggregate_route_origin_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/aggregate-route/match-med
 */
int bgp_global_afi_safis_afi_safi_ipv6_multicast_aggregate_route_match_med_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/aggregate-route/suppress-map
 */
int bgp_global_afi_safis_afi_safi_ipv6_multicast_aggregate_route_suppress_map_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv6_multicast_aggregate_route_suppress_map_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/admin-distance-route
 */
int bgp_global_afi_safis_afi_safi_ipv6_multicast_admin_distance_route_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv6_multicast_admin_distance_route_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_global_afi_safi_admin_distance_route_destroy(args);
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/admin-distance
 */
void bgp_global_afi_safis_afi_safi_ipv6_multicast_admin_distance_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	bgp_global_afi_safis_admin_distance_modify(args);
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/admin-distance/external
 */
int bgp_global_afi_safis_afi_safi_ipv6_multicast_admin_distance_external_modify(
	struct nb_cb_modify_args *args)
{
	/* Handled in admin_distance_apply_finish callback */

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/admin-distance/internal
 */
int bgp_global_afi_safis_afi_safi_ipv6_multicast_admin_distance_internal_modify(
	struct nb_cb_modify_args *args)
{
	/* Handled in admin_distance_apply_finish callback */

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/admin-distance/local
 */
int bgp_global_afi_safis_afi_safi_ipv6_multicast_admin_distance_local_modify(
	struct nb_cb_modify_args *args)
{
	/* Handled in admin_distance_apply_finish callback */

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-flowspec/flow-spec-config/interface
 */
int bgp_global_afi_safis_afi_safi_ipv4_flowspec_flow_spec_config_interface_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_flowspec_flow_spec_config_interface_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l3vpn-ipv4-unicast/network-config
 */
int bgp_global_afi_safis_afi_safi_l3vpn_ipv4_unicast_network_config_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_l3vpn_ipv4_unicast_network_config_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l3vpn-ipv4-unicast/network-config/prefix-list
 */
int bgp_global_afi_safis_afi_safi_l3vpn_ipv4_unicast_network_config_prefix_list_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_l3vpn_ipv4_unicast_network_config_prefix_list_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l3vpn-ipv4-unicast/network-config/prefix-list/label-index
 */
int bgp_global_afi_safis_afi_safi_l3vpn_ipv4_unicast_network_config_prefix_list_label_index_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l3vpn-ipv4-unicast/network-config/prefix-list/rmap-policy-export
 */
int bgp_global_afi_safis_afi_safi_l3vpn_ipv4_unicast_network_config_prefix_list_rmap_policy_export_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_l3vpn_ipv4_unicast_network_config_prefix_list_rmap_policy_export_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l3vpn-ipv6-unicast/network-config
 */
int bgp_global_afi_safis_afi_safi_l3vpn_ipv6_unicast_network_config_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_l3vpn_ipv6_unicast_network_config_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l3vpn-ipv6-unicast/network-config/prefix-list
 */
int bgp_global_afi_safis_afi_safi_l3vpn_ipv6_unicast_network_config_prefix_list_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_l3vpn_ipv6_unicast_network_config_prefix_list_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l3vpn-ipv6-unicast/network-config/prefix-list/label-index
 */
int bgp_global_afi_safis_afi_safi_l3vpn_ipv6_unicast_network_config_prefix_list_label_index_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/l3vpn-ipv6-unicast/network-config/prefix-list/rmap-policy-export
 */
int bgp_global_afi_safis_afi_safi_l3vpn_ipv6_unicast_network_config_prefix_list_rmap_policy_export_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_l3vpn_ipv6_unicast_network_config_prefix_list_rmap_policy_export_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/ipv4-unicast/common-config/pre-policy
 */
int bgp_global_bmp_config_target_list_afi_safis_afi_safi_ipv4_unicast_common_config_pre_policy_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/ipv4-unicast/common-config/post-policy
 */
int bgp_global_bmp_config_target_list_afi_safis_afi_safi_ipv4_unicast_common_config_post_policy_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/ipv4-multicast/common-config/pre-policy
 */
int bgp_global_bmp_config_target_list_afi_safis_afi_safi_ipv4_multicast_common_config_pre_policy_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/ipv4-multicast/common-config/post-policy
 */
int bgp_global_bmp_config_target_list_afi_safis_afi_safi_ipv4_multicast_common_config_post_policy_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/ipv6-unicast/common-config/pre-policy
 */
int bgp_global_bmp_config_target_list_afi_safis_afi_safi_ipv6_unicast_common_config_pre_policy_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/ipv6-unicast/common-config/post-policy
 */
int bgp_global_bmp_config_target_list_afi_safis_afi_safi_ipv6_unicast_common_config_post_policy_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/ipv6-multicast/common-config/pre-policy
 */
int bgp_global_bmp_config_target_list_afi_safis_afi_safi_ipv6_multicast_common_config_pre_policy_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/bmp-config/target-list/afi-safis/afi-safi/ipv6-multicast/common-config/post-policy
 */
int bgp_global_bmp_config_target_list_afi_safis_afi_safi_ipv6_multicast_common_config_post_policy_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

static int bgp_neighbor_afi_safi_flag_modify(struct nb_cb_modify_args *args,
					     uint32_t flags, bool set)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	const struct lyd_node *nbr_dnode;
	const struct lyd_node *nbr_af_dnode;
	const char *af_name;
	afi_t afi;
	safi_t safi;

	nbr_af_dnode = yang_dnode_get_parent(args->dnode, "afi-safi");
	af_name = yang_dnode_get_string(nbr_af_dnode, "./afi-safi-name");
	yang_afi_safi_identity2value(af_name, &afi, &safi);

	nbr_dnode = yang_dnode_get_parent(nbr_af_dnode, "neighbor");
	bgp = nb_running_get_entry(nbr_dnode, NULL, true);
	peer_str = yang_dnode_get_string(nbr_dnode, "./remote-address");
	peer = bgp_neighbor_peer_lookup(bgp, peer_str, args->errmsg,
					args->errmsg_len);

	if (peer_af_flag_modify_nb(peer, afi, safi, flags, set, args->errmsg,
				   args->errmsg_len)
	    < 0)
		return NB_ERR_INCONSISTENCY;

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/add-paths/path-type
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_add_paths_path_type_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/as-path-options/allow-own-as
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/as-path-options/allow-own-origin-as
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/as-path-options/replace-peer-as
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_AS_OVERRIDE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

static int
bgp_peer_afi_safi_default_originate_apply(struct nb_cb_apply_finish_args *args,
					  struct peer *peer, afi_t afi,
					  safi_t safi)
{
	bool originate = false;
	int ret = 0;
	struct route_map *route_map = NULL;
	const char *rmap = NULL;

	originate = yang_dnode_get_bool(args->dnode, "./originate");

	if (yang_dnode_exists(args->dnode, "./route-map")) {
		rmap = yang_dnode_get_string(args->dnode, "./route-map");
		route_map = route_map_lookup_by_name(rmap);
		if (!route_map) {
			snprintf(args->errmsg, args->errmsg_len,
				 "The route-map '%s' does not exist.", rmap);
			return -1;
		}
	}

	// zlog_debug("%s: originate %u route-map %s", __func__, originate,
	// rmap);
	if (originate)
		ret = peer_default_originate_set(peer, afi, safi, rmap,
						 route_map);
	else
		ret = peer_default_originate_unset(peer, afi, safi);

	return bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret);
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/default-originate
 */
void bgp_neighbor_afi_safi_default_originate_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	const struct lyd_node *nbr_dnode;
	const struct lyd_node *nbr_af_dnode;
	const char *af_name;
	afi_t afi;
	safi_t safi;

	nbr_af_dnode = yang_dnode_get_parent(args->dnode, "afi-safi");
	af_name = yang_dnode_get_string(nbr_af_dnode, "./afi-safi-name");
	yang_afi_safi_identity2value(af_name, &afi, &safi);

	nbr_dnode = yang_dnode_get_parent(nbr_af_dnode, "neighbor");
	bgp = nb_running_get_entry(nbr_dnode, NULL, true);
	peer_str = yang_dnode_get_string(nbr_dnode, "./remote-address");
	peer = bgp_neighbor_peer_lookup(bgp, peer_str, args->errmsg,
					args->errmsg_len);
	if (!peer)
		return;

	bgp_peer_afi_safi_default_originate_apply(args, peer, afi, safi);
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/default-originate/originate
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_default_originate_originate_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/default-originate/route-map
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_default_originate_route_map_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_default_originate_route_map_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

static int
bgp_neighbor_afi_safi_prefix_limit_list_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	const struct lyd_node *nbr_dnode;
	const struct lyd_node *nbr_af_dnode;
	const char *af_name;
	afi_t afi;
	safi_t safi;
	int direction;

	nbr_af_dnode = yang_dnode_get_parent(args->dnode, "afi-safi");
	af_name = yang_dnode_get_string(nbr_af_dnode, "./afi-safi-name");
	yang_afi_safi_identity2value(af_name, &afi, &safi);

	nbr_dnode = yang_dnode_get_parent(nbr_af_dnode, "neighbor");
	bgp = nb_running_get_entry(nbr_dnode, NULL, true);
	peer_str = yang_dnode_get_string(nbr_dnode, "./remote-address");
	peer = bgp_neighbor_peer_lookup(bgp, peer_str, args->errmsg,
					args->errmsg_len);
	if (!peer)
		return NB_ERR_INCONSISTENCY;

	direction = yang_dnode_get_enum(args->dnode, "./direction");

	switch (direction) {
	case 1:
		peer_maximum_prefix_unset(peer, afi, safi);
		break;
	case 2:
		UNSET_FLAG(peer->af_flags[afi][safi], PEER_FLAG_MAX_PREFIX_OUT);
		peer->pmax_out[afi][safi] = 0;
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_prefix_limit_list_destroy(args);
	}

	return NB_OK;
}

static void
bgp_peer_afi_safi_maximum_prefix_set(struct nb_cb_apply_finish_args *args,
				     struct peer *peer, afi_t afi, safi_t safi)
{
	int direction;
	uint32_t max;
	uint8_t threshold = MAXIMUM_PREFIX_THRESHOLD_DEFAULT;
	uint16_t restart = 0;
	bool warning = false;
	bool force;

	max = yang_dnode_get_uint32(args->dnode, "./max-prefixes");
	direction = yang_dnode_get_enum(args->dnode, "./direction");
	switch (direction) {
	case 1:
		force = yang_dnode_get_bool(args->dnode, "./force-check");

		if (yang_dnode_exists(args->dnode,
				      "./options/shutdown-threshold-pct"))
			threshold = yang_dnode_get_uint8(
				args->dnode,
				"./options/shutdown-threshold-pct");
		if (yang_dnode_exists(args->dnode,
				      "./options/tw-shutdown-threshold-pct"))
			threshold = yang_dnode_get_uint8(
				args->dnode,
				"./options/tw-shutdown-threshold-pct");
		if (yang_dnode_exists(args->dnode,
				      "./options/tr-shutdown-threshold-pct"))
			threshold = yang_dnode_get_uint8(
				args->dnode,
				"./options/tr-shutdown-threshold-pct");

		if (yang_dnode_exists(args->dnode, "./options/warning-only"))
			warning = yang_dnode_get_bool(args->dnode,
						      "./options/warning-only");
		if (yang_dnode_exists(args->dnode, "./options/tw-warning-only"))
			warning = yang_dnode_get_bool(
				args->dnode, "./options/tw-warning-only");

		if (yang_dnode_exists(args->dnode, "./options/restart-timer"))
			restart = yang_dnode_get_uint16(
				args->dnode, "./options/restart-timer");
		if (yang_dnode_exists(args->dnode,
				      "./options/tr-restart-timer"))
			restart = yang_dnode_get_uint16(
				args->dnode, "./options/tr-restart-timer");

		peer_maximum_prefix_set(peer, afi, safi, max, threshold,
					warning, restart, force);

		break;
	case 2:
		SET_FLAG(peer->af_flags[afi][safi], PEER_FLAG_MAX_PREFIX_OUT);
		peer->pmax_out[afi][safi] = max;

		break;
	}
}

void bgp_neighbors_neighbor_afi_safi_prefix_limit_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	const struct lyd_node *nbr_dnode;
	const struct lyd_node *nbr_af_dnode;
	const char *af_name;
	afi_t afi;
	safi_t safi;

	nbr_af_dnode = yang_dnode_get_parent(args->dnode, "afi-safi");
	af_name = yang_dnode_get_string(nbr_af_dnode, "./afi-safi-name");
	yang_afi_safi_identity2value(af_name, &afi, &safi);

	nbr_dnode = yang_dnode_get_parent(nbr_af_dnode, "neighbor");
	bgp = nb_running_get_entry(nbr_dnode, NULL, true);
	peer_str = yang_dnode_get_string(nbr_dnode, "./remote-address");
	peer = bgp_neighbor_peer_lookup(bgp, peer_str, args->errmsg,
					args->errmsg_len);
	if (!peer)
		return;

	bgp_peer_afi_safi_maximum_prefix_set(args, peer, afi, safi);
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/max-prefixes
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_max_prefixes_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/force-check
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_force_check_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/warning-only
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/restart-timer
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/tr-restart-timer
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/tw-warning-only
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/nexthop-self/next-hop-self
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/nexthop-self/next-hop-self-force
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_FORCE_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/private-as/remove-private-as-all
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_private_as_remove_private_as_all_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_ALL,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/private-as/remove-private-as-all-replace
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_private_as_remove_private_as_all_replace_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/private-as/remove-private-as
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_private_as_remove_private_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/private-as/remove-private-as-replace
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_private_as_remove_private_as_replace_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

static int bgp_neighbor_afi_safi_weight_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	const struct lyd_node *nbr_dnode;
	const struct lyd_node *nbr_af_dnode;
	const char *af_name;
	uint16_t weight;
	afi_t afi;
	safi_t safi;
	int ret;

	nbr_af_dnode = yang_dnode_get_parent(args->dnode, "afi-safi");
	af_name = yang_dnode_get_string(nbr_af_dnode, "./afi-safi-name");
	yang_afi_safi_identity2value(af_name, &afi, &safi);

	nbr_dnode = yang_dnode_get_parent(nbr_af_dnode, "neighbor");
	bgp = nb_running_get_entry(nbr_dnode, NULL, true);
	peer_str = yang_dnode_get_string(nbr_dnode, "./remote-address");
	peer = bgp_neighbor_peer_lookup(bgp, peer_str, args->errmsg,
					args->errmsg_len);

	weight = yang_dnode_get_uint16(args->dnode, NULL);

	ret = peer_weight_set(peer, afi, safi, weight);
	if (bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret) < 0)
		return NB_ERR_INCONSISTENCY;

	return NB_OK;
}

static int bgp_neighbor_afi_safi_weight_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	const struct lyd_node *nbr_dnode;
	const struct lyd_node *nbr_af_dnode;
	const char *af_name;
	afi_t afi;
	safi_t safi;
	int ret;

	nbr_af_dnode = yang_dnode_get_parent(args->dnode, "afi-safi");
	af_name = yang_dnode_get_string(nbr_af_dnode, "./afi-safi-name");
	yang_afi_safi_identity2value(af_name, &afi, &safi);

	nbr_dnode = yang_dnode_get_parent(nbr_af_dnode, "neighbor");
	bgp = nb_running_get_entry(nbr_dnode, NULL, true);
	peer_str = yang_dnode_get_string(nbr_dnode, "./remote-address");
	peer = bgp_neighbor_peer_lookup(bgp, peer_str, args->errmsg,
					args->errmsg_len);

	ret = peer_weight_unset(peer, afi, safi);
	if (bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret) < 0)
		return NB_ERR_INCONSISTENCY;

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/weight/weight-attribute
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_weight_weight_attribute_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_weight_modify(args);

		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_weight_weight_attribute_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_weight_destroy(args);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/route-reflector/route-reflector-client
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REFLECTOR_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/route-server/route-server-client
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_RSERVER_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/send-community/send-community
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_send_community_send_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/send-community/send-ext-community
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_send_community_send_ext_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_EXT_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/send-community/send-large-community
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_send_community_send_large_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_LARGE_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/soft-reconfiguration
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SOFT_RECONFIG,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/attr-unchanged/as-path-unchanged
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_AS_PATH_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/attr-unchanged/next-hop-unchanged
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/attr-unchanged/med-unchanged
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_MED_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/orf-capability/orf-send
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_send_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_send_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/orf-capability/orf-receive
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_receive_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_receive_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/orf-capability/orf-both
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_both_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_both_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/rmap-import
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_import_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_import_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/rmap-export
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_export_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_export_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/plist-import
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_plist_import_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_plist_import_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/plist-export
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_plist_export_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_plist_export_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/access-list-import
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_access_list_import_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_access_list_import_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/access-list-export
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_access_list_export_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_access_list_export_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/as-path-filter-list-import
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_as_path_filter_list_import_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_as_path_filter_list_import_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/as-path-filter-list-export
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_as_path_filter_list_export_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_as_path_filter_list_export_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/unsuppress-map-import
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_unsuppress_map_import_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_unsuppress_map_import_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/unsuppress-map-export
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_unsuppress_map_export_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_unsuppress_map_export_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/nexthop-local-unchanged
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_nexthop_local_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/add-paths/path-type
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_add_paths_path_type_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/as-path-options/allow-own-as
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/as-path-options/allow-own-origin-as
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/as-path-options/replace-peer-as
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_AS_OVERRIDE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/default-originate/originate
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_default_originate_originate_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/default-originate/route-map
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_default_originate_route_map_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_default_originate_route_map_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/attr-unchanged/as-path-unchanged
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_AS_PATH_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/attr-unchanged/next-hop-unchanged
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/attr-unchanged/med-unchanged
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_MED_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/orf-capability/orf-send
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_send_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_send_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/orf-capability/orf-receive
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_receive_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_receive_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/orf-capability/orf-both
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_both_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_both_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_prefix_limit_list_destroy(args);
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/max-prefixes
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_max_prefixes_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/force-check
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_force_check_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/warning-only
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/restart-timer
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/tr-restart-timer
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/tw-warning-only
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/nexthop-self/next-hop-self
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/nexthop-self/next-hop-self-force
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_FORCE_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/private-as/remove-private-as-all
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_private_as_remove_private_as_all_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_ALL,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/private-as/remove-private-as-all-replace
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_private_as_remove_private_as_all_replace_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/private-as/remove-private-as
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_private_as_remove_private_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/private-as/remove-private-as-replace
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_private_as_remove_private_as_replace_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/route-reflector/route-reflector-client
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REFLECTOR_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/route-server/route-server-client
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_RSERVER_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/send-community/send-community
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_send_community_send_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/send-community/send-ext-community
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_send_community_send_ext_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_EXT_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/send-community/send-large-community
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_send_community_send_large_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_LARGE_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/soft-reconfiguration
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SOFT_RECONFIG,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/weight/weight-attribute
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_weight_weight_attribute_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_weight_modify(args);

		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_weight_weight_attribute_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_weight_destroy(args);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/add-paths/path-type
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_add_paths_path_type_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/as-path-options/allow-own-as
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/as-path-options/allow-own-origin-as
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/as-path-options/replace-peer-as
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_AS_OVERRIDE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/default-originate/originate
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_default_originate_originate_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/default-originate/route-map
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_default_originate_route_map_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_default_originate_route_map_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/attr-unchanged/as-path-unchanged
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_AS_PATH_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/attr-unchanged/next-hop-unchanged
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/attr-unchanged/med-unchanged
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_MED_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/orf-capability/orf-send
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_send_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_send_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/orf-capability/orf-receive
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_receive_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_receive_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/orf-capability/orf-both
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_both_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_both_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_prefix_limit_list_destroy(args);
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/max-prefixes
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_max_prefixes_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/force-check
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_force_check_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/warning-only
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/restart-timer
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/shutdown-threshold-pct
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/tr-restart-timer
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/tw-warning-only
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/nexthop-self/next-hop-self
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/nexthop-self/next-hop-self-force
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_FORCE_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/private-as/remove-private-as-all
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_private_as_remove_private_as_all_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_ALL,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/private-as/remove-private-as-all-replace
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_private_as_remove_private_as_all_replace_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/private-as/remove-private-as
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_private_as_remove_private_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/private-as/remove-private-as-replace
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_private_as_remove_private_as_replace_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/route-reflector/route-reflector-client
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REFLECTOR_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/route-server/route-server-client
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_RSERVER_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/send-community/send-community
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_send_community_send_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/send-community/send-ext-community
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_send_community_send_ext_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_EXT_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/send-community/send-large-community
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_send_community_send_large_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_LARGE_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/soft-reconfiguration
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SOFT_RECONFIG,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/weight/weight-attribute
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_weight_weight_attribute_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_weight_modify(args);

		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_weight_weight_attribute_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_weight_destroy(args);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/add-paths/path-type
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_add_paths_path_type_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/as-path-options/allow-own-as
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/as-path-options/allow-own-origin-as
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/as-path-options/replace-peer-as
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_AS_OVERRIDE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/default-originate/originate
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_default_originate_originate_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/default-originate/route-map
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_default_originate_route_map_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_default_originate_route_map_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/attr-unchanged/as-path-unchanged
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_AS_PATH_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/attr-unchanged/next-hop-unchanged
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/attr-unchanged/med-unchanged
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_MED_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/orf-capability/orf-send
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_send_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_send_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/orf-capability/orf-receive
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_receive_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_receive_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/orf-capability/orf-both
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_both_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_both_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_prefix_limit_list_destroy(args);
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/max-prefixes
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_max_prefixes_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/force-check
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_force_check_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/warning-only
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/restart-timer
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/shutdown-threshold-pct
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/tr-restart-timer
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/tw-warning-only
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/nexthop-self/next-hop-self
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/nexthop-self/next-hop-self-force
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_FORCE_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/private-as/remove-private-as-all
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_private_as_remove_private_as_all_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_ALL,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/private-as/remove-private-as-all-replace
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_private_as_remove_private_as_all_replace_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/private-as/remove-private-as
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_private_as_remove_private_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/private-as/remove-private-as-replace
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_private_as_remove_private_as_replace_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/route-reflector/route-reflector-client
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REFLECTOR_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/route-server/route-server-client
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_RSERVER_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/send-community/send-community
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_send_community_send_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/send-community/send-ext-community
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_send_community_send_ext_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_EXT_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/send-community/send-large-community
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_send_community_send_large_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_LARGE_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/soft-reconfiguration
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SOFT_RECONFIG,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/weight/weight-attribute
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_weight_weight_attribute_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_weight_modify(args);

		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_weight_weight_attribute_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_weight_destroy(args);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/add-paths/path-type
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_add_paths_path_type_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/as-path-options/allow-own-as
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/as-path-options/allow-own-origin-as
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/as-path-options/replace-peer-as
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_AS_OVERRIDE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/default-originate/originate
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_default_originate_originate_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/default-originate/route-map
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_default_originate_route_map_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_default_originate_route_map_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/attr-unchanged/as-path-unchanged
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_AS_PATH_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/attr-unchanged/next-hop-unchanged
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/attr-unchanged/med-unchanged
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_MED_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/orf-capability/orf-send
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_send_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_send_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/orf-capability/orf-receive
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_receive_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_receive_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/orf-capability/orf-both
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_both_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_both_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_prefix_limit_list_destroy(args);
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/max-prefixes
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_max_prefixes_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/force-check
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_force_check_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/warning-only
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/restart-timer
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/tr-restart-timer
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/tw-warning-only
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/nexthop-self/next-hop-self
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/nexthop-self/next-hop-self-force
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_FORCE_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/private-as/remove-private-as-all
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_private_as_remove_private_as_all_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_ALL,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/private-as/remove-private-as-all-replace
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_private_as_remove_private_as_all_replace_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/private-as/remove-private-as
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_private_as_remove_private_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/private-as/remove-private-as-replace
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_private_as_remove_private_as_replace_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/route-reflector/route-reflector-client
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REFLECTOR_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/route-server/route-server-client
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_RSERVER_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/send-community/send-community
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_send_community_send_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/send-community/send-ext-community
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_send_community_send_ext_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_EXT_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/send-community/send-large-community
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_send_community_send_large_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_LARGE_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/soft-reconfiguration
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SOFT_RECONFIG,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/weight/weight-attribute
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_weight_weight_attribute_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_weight_modify(args);

		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_weight_weight_attribute_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_weight_destroy(args);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/add-paths/path-type
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_add_paths_path_type_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/as-path-options/allow-own-as
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/as-path-options/allow-own-origin-as
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/as-path-options/replace-peer-as
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_AS_OVERRIDE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/default-originate/originate
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_default_originate_originate_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/default-originate/route-map
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_default_originate_route_map_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_default_originate_route_map_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/attr-unchanged/as-path-unchanged
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_AS_PATH_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/attr-unchanged/next-hop-unchanged
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/attr-unchanged/med-unchanged
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_MED_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/orf-capability/orf-send
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_send_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_send_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/orf-capability/orf-receive
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_receive_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_receive_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/orf-capability/orf-both
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_both_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_both_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_prefix_limit_list_destroy(args);
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/max-prefixes
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_max_prefixes_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/force-check
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_force_check_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/warning-only
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/restart-timer
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/tr-restart-timer
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/tw-warning-only
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/nexthop-self/next-hop-self
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/nexthop-self/next-hop-self-force
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_FORCE_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/private-as/remove-private-as-all
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_private_as_remove_private_as_all_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_ALL,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/private-as/remove-private-as-all-replace
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_private_as_remove_private_as_all_replace_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/private-as/remove-private-as
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_private_as_remove_private_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/private-as/remove-private-as-replace
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_private_as_remove_private_as_replace_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/route-reflector/route-reflector-client
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REFLECTOR_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/route-server/route-server-client
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_RSERVER_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/send-community/send-community
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_send_community_send_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/send-community/send-ext-community
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_send_community_send_ext_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_EXT_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/send-community/send-large-community
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_send_community_send_large_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_LARGE_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/soft-reconfiguration
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SOFT_RECONFIG,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/weight/weight-attribute
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_weight_weight_attribute_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_weight_modify(args);

		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_weight_weight_attribute_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_weight_destroy(args);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/add-paths/path-type
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_add_paths_path_type_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/as-path-options/allow-own-as
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/as-path-options/allow-own-origin-as
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/as-path-options/replace-peer-as
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_AS_OVERRIDE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/attr-unchanged/as-path-unchanged
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_AS_PATH_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/attr-unchanged/next-hop-unchanged
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/attr-unchanged/med-unchanged
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_MED_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_prefix_limit_list_destroy(args);
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/max-prefixes
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_max_prefixes_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/force-check
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_force_check_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/warning-only
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/restart-timer
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/tr-restart-timer
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/tw-warning-only
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/nexthop-self/next-hop-self
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/nexthop-self/next-hop-self-force
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_FORCE_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/private-as/remove-private-as-all
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_private_as_remove_private_as_all_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_ALL,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/private-as/remove-private-as-all-replace
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_private_as_remove_private_as_all_replace_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/private-as/remove-private-as
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_private_as_remove_private_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/private-as/remove-private-as-replace
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_private_as_remove_private_as_replace_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/route-reflector/route-reflector-client
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REFLECTOR_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/route-server/route-server-client
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_RSERVER_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/send-community/send-community
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_send_community_send_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/send-community/send-ext-community
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_send_community_send_ext_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_EXT_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/send-community/send-large-community
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_send_community_send_large_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_LARGE_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/soft-reconfiguration
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SOFT_RECONFIG,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/weight/weight-attribute
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_weight_weight_attribute_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_weight_modify(args);

		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_weight_weight_attribute_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_weight_destroy(args);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/add-paths/path-type
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_add_paths_path_type_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/as-path-options/allow-own-as
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/as-path-options/allow-own-origin-as
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/as-path-options/replace-peer-as
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_AS_OVERRIDE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/attr-unchanged/as-path-unchanged
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_AS_PATH_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/attr-unchanged/next-hop-unchanged
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/attr-unchanged/med-unchanged
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_MED_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_prefix_limit_list_destroy(args);
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/max-prefixes
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_max_prefixes_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/force-check
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_force_check_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/warning-only
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/restart-timer
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/tr-restart-timer
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/tw-warning-only
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/nexthop-self/next-hop-self
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/nexthop-self/next-hop-self-force
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_FORCE_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/private-as/remove-private-as-all
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_private_as_remove_private_as_all_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_ALL,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/private-as/remove-private-as-all-replace
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_private_as_remove_private_as_all_replace_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/private-as/remove-private-as
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_private_as_remove_private_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/private-as/remove-private-as-replace
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_private_as_remove_private_as_replace_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/route-reflector/route-reflector-client
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REFLECTOR_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/route-server/route-server-client
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_RSERVER_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/send-community/send-community
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_send_community_send_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/send-community/send-ext-community
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_send_community_send_ext_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_EXT_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/send-community/send-large-community
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_send_community_send_large_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_LARGE_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/soft-reconfiguration
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SOFT_RECONFIG,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/weight/weight-attribute
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_weight_weight_attribute_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_weight_modify(args);

		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_weight_weight_attribute_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_weight_destroy(args);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/as-path-options/allow-own-as
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/as-path-options/allow-own-origin-as
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/as-path-options/replace-peer-as
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_AS_OVERRIDE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/attr-unchanged/as-path-unchanged
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_AS_PATH_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/attr-unchanged/next-hop-unchanged
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/attr-unchanged/med-unchanged
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_MED_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/nexthop-self/next-hop-self
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/nexthop-self/next-hop-self-force
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_FORCE_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/route-reflector/route-reflector-client
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REFLECTOR_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/route-server/route-server-client
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_RSERVER_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l2vpn-evpn/soft-reconfiguration
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l2vpn_evpn_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SOFT_RECONFIG,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-flowspec/route-reflector/route-reflector-client
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_flowspec_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REFLECTOR_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-flowspec/route-server/route-server-client
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_flowspec_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_RSERVER_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-flowspec/soft-reconfiguration
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_flowspec_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SOFT_RECONFIG,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-flowspec/route-reflector/route-reflector-client
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_flowspec_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REFLECTOR_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-flowspec/route-server/route-server-client
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_flowspec_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_RSERVER_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-flowspec/soft-reconfiguration
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_flowspec_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SOFT_RECONFIG,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

static int
bgp_unnumbered_neighbor_afi_safi_flag_modify(struct nb_cb_modify_args *args,
					     uint32_t flags, bool set)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	const struct lyd_node *nbr_dnode;
	const struct lyd_node *nbr_af_dnode;
	const char *af_name;
	afi_t afi;
	safi_t safi;

	nbr_af_dnode = yang_dnode_get_parent(args->dnode, "afi-safi");
	af_name = yang_dnode_get_string(nbr_af_dnode, "./afi-safi-name");
	yang_afi_safi_identity2value(af_name, &afi, &safi);

	nbr_dnode = yang_dnode_get_parent(nbr_af_dnode, "unnumbered-neighbor");
	bgp = nb_running_get_entry(nbr_dnode, NULL, true);
	peer_str = yang_dnode_get_string(nbr_dnode, "./interface");
	peer = bgp_unnumbered_neighbor_peer_lookup(bgp, peer_str, args->errmsg,
						   args->errmsg_len);

	if (peer_af_flag_modify_nb(peer, afi, safi, flags, set, args->errmsg,
				   args->errmsg_len)
	    < 0)
		return NB_ERR_INCONSISTENCY;

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/add-paths/path-type
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_add_paths_path_type_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/as-path-options/allow-own-as
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/as-path-options/allow-own-origin-as
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/as-path-options/replace-peer-as
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_AS_OVERRIDE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/default-originate
 */
void bgp_unnumbered_neighbor_afi_safi_default_originate_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	const struct lyd_node *nbr_dnode;
	const struct lyd_node *nbr_af_dnode;
	const char *af_name;
	afi_t afi;
	safi_t safi;

	nbr_af_dnode = yang_dnode_get_parent(args->dnode, "afi-safi");
	af_name = yang_dnode_get_string(nbr_af_dnode, "./afi-safi-name");
	yang_afi_safi_identity2value(af_name, &afi, &safi);

	nbr_dnode = yang_dnode_get_parent(nbr_af_dnode, "unnumbered-neighbor");
	bgp = nb_running_get_entry(nbr_dnode, NULL, true);
	peer_str = yang_dnode_get_string(nbr_dnode, "./interface");
	peer = bgp_unnumbered_neighbor_peer_lookup(bgp, peer_str, args->errmsg,
						   args->errmsg_len);
	if (!peer)
		return;

	bgp_peer_afi_safi_default_originate_apply(args, peer, afi, safi);
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/default-originate/originate
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_default_originate_originate_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/default-originate/route-map
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_default_originate_route_map_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_default_originate_route_map_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

static int bgp_unnumbered_neighbor_afi_safi_prefix_limit_list_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	const struct lyd_node *nbr_dnode;
	const struct lyd_node *nbr_af_dnode;
	const char *af_name;
	afi_t afi;
	safi_t safi;
	int direction;

	nbr_af_dnode = yang_dnode_get_parent(args->dnode, "afi-safi");
	af_name = yang_dnode_get_string(nbr_af_dnode, "./afi-safi-name");
	yang_afi_safi_identity2value(af_name, &afi, &safi);

	nbr_dnode = yang_dnode_get_parent(nbr_af_dnode, "unnumbered-neighbor");
	bgp = nb_running_get_entry(nbr_dnode, NULL, true);
	peer_str = yang_dnode_get_string(nbr_dnode, "./interface");
	peer = bgp_unnumbered_neighbor_peer_lookup(bgp, peer_str, args->errmsg,
						   args->errmsg_len);
	if (!peer)
		return NB_ERR_INCONSISTENCY;

	direction = yang_dnode_get_enum(args->dnode, "./direction");

	switch (direction) {
	case 1:
		peer_maximum_prefix_unset(peer, afi, safi);
		break;
	case 2:
		UNSET_FLAG(peer->af_flags[afi][safi], PEER_FLAG_MAX_PREFIX_OUT);
		peer->pmax_out[afi][safi] = 0;
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_prefix_limit_list_destroy(
			args);
	}

	return NB_OK;
}

void bgp_unnumbered_neighbor_afi_safi_prefix_limit_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	const struct lyd_node *nbr_dnode;
	const struct lyd_node *nbr_af_dnode;
	const char *af_name;
	afi_t afi;
	safi_t safi;

	nbr_af_dnode = yang_dnode_get_parent(args->dnode, "afi-safi");
	af_name = yang_dnode_get_string(nbr_af_dnode, "./afi-safi-name");
	yang_afi_safi_identity2value(af_name, &afi, &safi);

	nbr_dnode = yang_dnode_get_parent(nbr_af_dnode, "unnumbered-neighbor");
	bgp = nb_running_get_entry(nbr_dnode, NULL, true);
	peer_str = yang_dnode_get_string(nbr_dnode, "./interface");
	peer = bgp_unnumbered_neighbor_peer_lookup(bgp, peer_str, args->errmsg,
						   args->errmsg_len);
	if (!peer)
		return;

	bgp_peer_afi_safi_maximum_prefix_set(args, peer, afi, safi);
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/max-prefixes
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_max_prefixes_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/force-check
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_force_check_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/warning-only
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/restart-timer
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/tr-restart-timer
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/tw-warning-only
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/nexthop-self/next-hop-self
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/nexthop-self/next-hop-self-force
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_FORCE_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/private-as/remove-private-as-all
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_private_as_remove_private_as_all_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_ALL,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/private-as/remove-private-as-all-replace
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_private_as_remove_private_as_all_replace_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/private-as/remove-private-as
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_private_as_remove_private_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/private-as/remove-private-as-replace
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_private_as_remove_private_as_replace_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

static int
bgp_unnumbered_neighbor_afi_safi_weight_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	const struct lyd_node *nbr_dnode;
	const char *af_name;
	uint16_t weight;
	afi_t afi;
	safi_t safi;
	const struct lyd_node *nbr_af_dnode;
	int ret;

	nbr_af_dnode = yang_dnode_get_parent(args->dnode, "afi-safi");
	af_name = yang_dnode_get_string(nbr_af_dnode, "./afi-safi-name");
	yang_afi_safi_identity2value(af_name, &afi, &safi);

	nbr_dnode = yang_dnode_get_parent(nbr_af_dnode, "unnumbered-neighbor");
	bgp = nb_running_get_entry(nbr_dnode, NULL, true);
	peer_str = yang_dnode_get_string(nbr_dnode, "./interface");
	peer = bgp_unnumbered_neighbor_peer_lookup(bgp, peer_str, args->errmsg,
						   args->errmsg_len);

	weight = yang_dnode_get_uint16(args->dnode, NULL);

	ret = peer_weight_set(peer, afi, safi, weight);
	if (bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret) < 0)
		return NB_ERR_INCONSISTENCY;

	return NB_OK;
}

static int
bgp_unnumbered_neighbor_afi_safi_weight_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	const struct lyd_node *nbr_dnode;
	const struct lyd_node *nbr_af_dnode;
	const char *af_name;
	afi_t afi;
	safi_t safi;
	int ret;

	bgp = nb_running_get_entry(args->dnode, NULL, true);
	nbr_dnode = yang_dnode_get_parent(args->dnode, "unnumbered-neighbor");
	peer_str = yang_dnode_get_string(nbr_dnode, "./interface");
	peer = bgp_unnumbered_neighbor_peer_lookup(bgp, peer_str, args->errmsg,
						   args->errmsg_len);
	nbr_af_dnode = yang_dnode_get_parent(args->dnode, "afi-safi");
	af_name = yang_dnode_get_string(nbr_af_dnode, "./afi-safi-name");
	yang_afi_safi_identity2value(af_name, &afi, &safi);

	ret = peer_weight_unset(peer, afi, safi);
	if (bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret) < 0)
		return NB_ERR_INCONSISTENCY;

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/weight/weight-attribute
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_weight_weight_attribute_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_weight_modify(args);

		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_weight_weight_attribute_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_weight_destroy(args);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/route-reflector/route-reflector-client
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REFLECTOR_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/route-server/route-server-client
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_RSERVER_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/send-community/send-community
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_send_community_send_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/send-community/send-ext-community
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_send_community_send_ext_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_EXT_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/send-community/send-large-community
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_send_community_send_large_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_LARGE_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/soft-reconfiguration
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SOFT_RECONFIG,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/attr-unchanged/as-path-unchanged
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_AS_PATH_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/attr-unchanged/next-hop-unchanged
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/attr-unchanged/med-unchanged
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_MED_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/orf-capability/orf-send
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_send_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_send_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/orf-capability/orf-receive
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_receive_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_receive_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/orf-capability/orf-both
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_both_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_both_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/rmap-import
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_import_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_import_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/rmap-export
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_export_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_export_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/plist-import
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_plist_import_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_plist_import_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/plist-export
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_plist_export_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_plist_export_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/access-list-import
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_access_list_import_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_access_list_import_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/access-list-export
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_access_list_export_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_access_list_export_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/as-path-filter-list-import
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_as_path_filter_list_import_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_as_path_filter_list_import_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/as-path-filter-list-export
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_as_path_filter_list_export_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_as_path_filter_list_export_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/unsuppress-map-import
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_unsuppress_map_import_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_unsuppress_map_import_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/unsuppress-map-export
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_unsuppress_map_export_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_unsuppress_map_export_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/nexthop-local-unchanged
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_nexthop_local_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/add-paths/path-type
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_add_paths_path_type_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/as-path-options/allow-own-as
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/as-path-options/allow-own-origin-as
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/as-path-options/replace-peer-as
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_AS_OVERRIDE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/default-originate/originate
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_default_originate_originate_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/default-originate/route-map
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_default_originate_route_map_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_default_originate_route_map_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/attr-unchanged/as-path-unchanged
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_AS_PATH_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/attr-unchanged/next-hop-unchanged
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/attr-unchanged/med-unchanged
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_MED_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/orf-capability/orf-send
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_send_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_send_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/orf-capability/orf-receive
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_receive_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_receive_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/orf-capability/orf-both
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_both_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_both_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_prefix_limit_list_destroy(
			args);
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/max-prefixes
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_max_prefixes_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/force-check
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_force_check_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/warning-only
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/restart-timer
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/tr-restart-timer
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/tw-warning-only
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/nexthop-self/next-hop-self
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/nexthop-self/next-hop-self-force
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_FORCE_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/private-as/remove-private-as-all
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_private_as_remove_private_as_all_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_ALL,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/private-as/remove-private-as-all-replace
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_private_as_remove_private_as_all_replace_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/private-as/remove-private-as
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_private_as_remove_private_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/private-as/remove-private-as-replace
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_private_as_remove_private_as_replace_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/route-reflector/route-reflector-client
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REFLECTOR_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/route-server/route-server-client
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_RSERVER_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/send-community/send-community
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_send_community_send_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/send-community/send-ext-community
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_send_community_send_ext_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_EXT_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/send-community/send-large-community
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_send_community_send_large_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_LARGE_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/soft-reconfiguration
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SOFT_RECONFIG,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/weight/weight-attribute
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_weight_weight_attribute_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_weight_modify(args);

		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_weight_weight_attribute_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_weight_destroy(args);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/add-paths/path-type
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_add_paths_path_type_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/as-path-options/allow-own-as
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/as-path-options/allow-own-origin-as
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/as-path-options/replace-peer-as
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_AS_OVERRIDE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/default-originate/originate
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_default_originate_originate_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/default-originate/route-map
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_default_originate_route_map_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_default_originate_route_map_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/attr-unchanged/as-path-unchanged
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_AS_PATH_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/attr-unchanged/next-hop-unchanged
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/attr-unchanged/med-unchanged
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_MED_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/orf-capability/orf-send
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_send_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_send_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/orf-capability/orf-receive
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_receive_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_receive_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/orf-capability/orf-both
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_both_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_both_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_prefix_limit_list_destroy(
			args);
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/max-prefixes
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_max_prefixes_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/force-check
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_force_check_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/warning-only
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/restart-timer
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/shutdown-threshold-pct
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/tr-restart-timer
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/tw-warning-only
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/nexthop-self/next-hop-self
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/nexthop-self/next-hop-self-force
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_FORCE_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/private-as/remove-private-as-all
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_private_as_remove_private_as_all_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_ALL,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/private-as/remove-private-as-all-replace
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_private_as_remove_private_as_all_replace_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/private-as/remove-private-as
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_private_as_remove_private_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/private-as/remove-private-as-replace
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_private_as_remove_private_as_replace_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/route-reflector/route-reflector-client
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REFLECTOR_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/route-server/route-server-client
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_RSERVER_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/send-community/send-community
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_send_community_send_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/send-community/send-ext-community
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_send_community_send_ext_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_EXT_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/send-community/send-large-community
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_send_community_send_large_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_LARGE_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/soft-reconfiguration
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SOFT_RECONFIG,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/weight/weight-attribute
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_weight_weight_attribute_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_weight_modify(args);

		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_weight_weight_attribute_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_weight_destroy(args);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/add-paths/path-type
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_add_paths_path_type_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/as-path-options/allow-own-as
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/as-path-options/allow-own-origin-as
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/as-path-options/replace-peer-as
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_AS_OVERRIDE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/default-originate/originate
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_default_originate_originate_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/default-originate/route-map
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_default_originate_route_map_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_default_originate_route_map_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/attr-unchanged/as-path-unchanged
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_AS_PATH_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/attr-unchanged/next-hop-unchanged
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/attr-unchanged/med-unchanged
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_MED_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/orf-capability/orf-send
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_send_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_send_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/orf-capability/orf-receive
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_receive_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_receive_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/orf-capability/orf-both
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_both_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_both_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_prefix_limit_list_destroy(
			args);
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/max-prefixes
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_max_prefixes_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/force-check
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_force_check_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/warning-only
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/restart-timer
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/shutdown-threshold-pct
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/tr-restart-timer
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/tw-warning-only
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/nexthop-self/next-hop-self
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/nexthop-self/next-hop-self-force
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_FORCE_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/private-as/remove-private-as-all
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_private_as_remove_private_as_all_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_ALL,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/private-as/remove-private-as-all-replace
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_private_as_remove_private_as_all_replace_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/private-as/remove-private-as
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_private_as_remove_private_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/private-as/remove-private-as-replace
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_private_as_remove_private_as_replace_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/route-reflector/route-reflector-client
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REFLECTOR_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/route-server/route-server-client
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_RSERVER_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/send-community/send-community
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_send_community_send_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/send-community/send-ext-community
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_send_community_send_ext_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_EXT_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/send-community/send-large-community
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_send_community_send_large_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_LARGE_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/soft-reconfiguration
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SOFT_RECONFIG,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/weight/weight-attribute
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_weight_weight_attribute_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_weight_modify(args);

		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_weight_weight_attribute_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_weight_destroy(args);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/add-paths/path-type
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_add_paths_path_type_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/as-path-options/allow-own-as
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/as-path-options/allow-own-origin-as
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/as-path-options/replace-peer-as
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_AS_OVERRIDE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/default-originate/originate
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_default_originate_originate_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/default-originate/route-map
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_default_originate_route_map_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_default_originate_route_map_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/attr-unchanged/as-path-unchanged
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_AS_PATH_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/attr-unchanged/next-hop-unchanged
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/attr-unchanged/med-unchanged
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_MED_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/orf-capability/orf-send
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_send_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_send_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/orf-capability/orf-receive
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_receive_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_receive_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/orf-capability/orf-both
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_both_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_both_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_prefix_limit_list_destroy(
			args);
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/max-prefixes
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_max_prefixes_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/force-check
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_force_check_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/warning-only
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/restart-timer
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/tr-restart-timer
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/tw-warning-only
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/nexthop-self/next-hop-self
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/nexthop-self/next-hop-self-force
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_FORCE_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/private-as/remove-private-as-all
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_private_as_remove_private_as_all_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_ALL,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/private-as/remove-private-as-all-replace
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_private_as_remove_private_as_all_replace_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/private-as/remove-private-as
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_private_as_remove_private_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/private-as/remove-private-as-replace
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_private_as_remove_private_as_replace_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/route-reflector/route-reflector-client
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REFLECTOR_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/route-server/route-server-client
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_RSERVER_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/send-community/send-community
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_send_community_send_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/send-community/send-ext-community
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_send_community_send_ext_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_EXT_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/send-community/send-large-community
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_send_community_send_large_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_LARGE_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/soft-reconfiguration
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SOFT_RECONFIG,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/weight/weight-attribute
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_weight_weight_attribute_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_weight_modify(args);

		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_weight_weight_attribute_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_weight_destroy(args);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/add-paths/path-type
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_add_paths_path_type_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/as-path-options/allow-own-as
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/as-path-options/allow-own-origin-as
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/as-path-options/replace-peer-as
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_AS_OVERRIDE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/default-originate/originate
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_default_originate_originate_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/default-originate/route-map
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_default_originate_route_map_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_default_originate_route_map_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/attr-unchanged/as-path-unchanged
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_AS_PATH_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/attr-unchanged/next-hop-unchanged
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/attr-unchanged/med-unchanged
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_MED_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/orf-capability/orf-send
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_send_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_send_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/orf-capability/orf-receive
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_receive_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_receive_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/orf-capability/orf-both
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_both_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_both_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_prefix_limit_list_destroy(
			args);
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/max-prefixes
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_max_prefixes_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/force-check
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_force_check_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/warning-only
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/restart-timer
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/tr-restart-timer
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/tw-warning-only
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/nexthop-self/next-hop-self
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/nexthop-self/next-hop-self-force
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_FORCE_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/private-as/remove-private-as-all
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_private_as_remove_private_as_all_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_ALL,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/private-as/remove-private-as-all-replace
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_private_as_remove_private_as_all_replace_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/private-as/remove-private-as
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_private_as_remove_private_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/private-as/remove-private-as-replace
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_private_as_remove_private_as_replace_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/route-reflector/route-reflector-client
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REFLECTOR_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/route-server/route-server-client
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_RSERVER_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/send-community/send-community
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_send_community_send_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/send-community/send-ext-community
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_send_community_send_ext_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_EXT_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/send-community/send-large-community
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_send_community_send_large_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_LARGE_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/soft-reconfiguration
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SOFT_RECONFIG,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/weight/weight-attribute
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_weight_weight_attribute_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_weight_modify(args);

		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_weight_weight_attribute_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_weight_destroy(args);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/add-paths/path-type
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_add_paths_path_type_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/as-path-options/allow-own-as
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/as-path-options/allow-own-origin-as
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/as-path-options/replace-peer-as
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_AS_OVERRIDE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/attr-unchanged/as-path-unchanged
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_AS_PATH_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/attr-unchanged/next-hop-unchanged
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/attr-unchanged/med-unchanged
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_MED_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_prefix_limit_list_destroy(
			args);
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/max-prefixes
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_max_prefixes_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/force-check
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_force_check_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/warning-only
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/restart-timer
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/tr-restart-timer
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/tw-warning-only
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/nexthop-self/next-hop-self
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/nexthop-self/next-hop-self-force
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_FORCE_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/private-as/remove-private-as-all
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_private_as_remove_private_as_all_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_ALL,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/private-as/remove-private-as-all-replace
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_private_as_remove_private_as_all_replace_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/private-as/remove-private-as
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_private_as_remove_private_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/private-as/remove-private-as-replace
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_private_as_remove_private_as_replace_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/route-reflector/route-reflector-client
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REFLECTOR_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/route-server/route-server-client
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_RSERVER_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/send-community/send-community
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_send_community_send_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/send-community/send-ext-community
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_send_community_send_ext_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_EXT_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/send-community/send-large-community
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_send_community_send_large_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_LARGE_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/soft-reconfiguration
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SOFT_RECONFIG,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/weight/weight-attribute
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_weight_weight_attribute_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_weight_modify(args);

		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_weight_weight_attribute_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_weight_destroy(args);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/add-paths/path-type
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_add_paths_path_type_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/as-path-options/allow-own-as
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/as-path-options/allow-own-origin-as
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/as-path-options/replace-peer-as
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_AS_OVERRIDE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/attr-unchanged/as-path-unchanged
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_AS_PATH_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/attr-unchanged/next-hop-unchanged
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/attr-unchanged/med-unchanged
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_MED_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_prefix_limit_list_destroy(
			args);
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/max-prefixes
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_max_prefixes_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/force-check
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_force_check_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/warning-only
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/restart-timer
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/tr-restart-timer
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/tw-warning-only
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/nexthop-self/next-hop-self
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/nexthop-self/next-hop-self-force
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_FORCE_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/private-as/remove-private-as-all
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_private_as_remove_private_as_all_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_ALL,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/private-as/remove-private-as-all-replace
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_private_as_remove_private_as_all_replace_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/private-as/remove-private-as
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_private_as_remove_private_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/private-as/remove-private-as-replace
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_private_as_remove_private_as_replace_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/route-reflector/route-reflector-client
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REFLECTOR_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/route-server/route-server-client
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_RSERVER_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/send-community/send-community
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_send_community_send_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/send-community/send-ext-community
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_send_community_send_ext_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_EXT_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/send-community/send-large-community
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_send_community_send_large_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_LARGE_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/soft-reconfiguration
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SOFT_RECONFIG,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/weight/weight-attribute
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_weight_weight_attribute_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_weight_modify(args);

		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_weight_weight_attribute_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_weight_destroy(args);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/as-path-options/allow-own-as
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/as-path-options/allow-own-origin-as
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/as-path-options/replace-peer-as
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_AS_OVERRIDE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/attr-unchanged/as-path-unchanged
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_AS_PATH_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/attr-unchanged/next-hop-unchanged
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/attr-unchanged/med-unchanged
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_MED_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/nexthop-self/next-hop-self
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/nexthop-self/next-hop-self-force
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_FORCE_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/route-reflector/route-reflector-client
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REFLECTOR_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/route-server/route-server-client
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_RSERVER_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l2vpn-evpn/soft-reconfiguration
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l2vpn_evpn_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SOFT_RECONFIG,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-flowspec/route-reflector/route-reflector-client
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_flowspec_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REFLECTOR_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-flowspec/route-server/route-server-client
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_flowspec_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_RSERVER_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-flowspec/soft-reconfiguration
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_flowspec_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SOFT_RECONFIG,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-flowspec/route-reflector/route-reflector-client
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_flowspec_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_REFLECTOR_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-flowspec/route-server/route-server-client
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_flowspec_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_RSERVER_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-flowspec/soft-reconfiguration
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_flowspec_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_unnumbered_neighbor_afi_safi_flag_modify(
			args, PEER_FLAG_SOFT_RECONFIG,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

static int bgp_peer_group_afi_safi_flag_modify(struct nb_cb_modify_args *args,
					       uint32_t flags, bool set)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	const struct lyd_node *nbr_dnode;
	const struct lyd_node *nbr_af_dnode;
	const char *af_name;
	afi_t afi;
	safi_t safi;

	nbr_af_dnode = yang_dnode_get_parent(args->dnode, "afi-safi");
	af_name = yang_dnode_get_string(nbr_af_dnode, "./afi-safi-name");
	yang_afi_safi_identity2value(af_name, &afi, &safi);
	nbr_dnode = yang_dnode_get_parent(nbr_af_dnode, "peer-group");
	bgp = nb_running_get_entry(nbr_dnode, NULL, true);
	peer_str = yang_dnode_get_string(nbr_dnode, "./peer-group-name");
	peer = bgp_peer_group_peer_lookup(bgp, peer_str);

	if (peer_af_flag_modify_nb(peer, afi, safi, flags, set, args->errmsg,
				   args->errmsg_len)
	    < 0)
		return NB_ERR_INCONSISTENCY;

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/add-paths/path-type
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_add_paths_path_type_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/as-path-options/allow-own-as
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/as-path-options/allow-own-origin-as
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/as-path-options/replace-peer-as
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_AS_OVERRIDE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/default-originate
 */
void bgp_peer_group_afi_safi_default_originate_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	const struct lyd_node *nbr_dnode;
	const struct lyd_node *nbr_af_dnode;
	const char *af_name;
	afi_t afi;
	safi_t safi;

	nbr_af_dnode = yang_dnode_get_parent(args->dnode, "afi-safi");
	af_name = yang_dnode_get_string(nbr_af_dnode, "./afi-safi-name");
	yang_afi_safi_identity2value(af_name, &afi, &safi);

	nbr_dnode = yang_dnode_get_parent(nbr_af_dnode, "peer-group");
	bgp = nb_running_get_entry(nbr_dnode, NULL, true);
	peer_str = yang_dnode_get_string(nbr_dnode, "./peer-group-name");
	peer = bgp_peer_group_peer_lookup(bgp, peer_str);
	if (!peer)
		return;

	bgp_peer_afi_safi_default_originate_apply(args, peer, afi, safi);
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/default-originate/originate
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_default_originate_originate_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/default-originate/route-map
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_default_originate_route_map_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_default_originate_route_map_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

static int bgp_peer_group_afi_safi_prefix_limit_list_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	const struct lyd_node *nbr_dnode;
	const struct lyd_node *nbr_af_dnode;
	const char *af_name;
	afi_t afi;
	safi_t safi;
	int direction;

	nbr_af_dnode = yang_dnode_get_parent(args->dnode, "afi-safi");
	af_name = yang_dnode_get_string(nbr_af_dnode, "./afi-safi-name");
	yang_afi_safi_identity2value(af_name, &afi, &safi);

	nbr_dnode = yang_dnode_get_parent(nbr_af_dnode, "peer-group");
	bgp = nb_running_get_entry(nbr_dnode, NULL, true);
	peer_str = yang_dnode_get_string(nbr_dnode, "./peer-group-name");
	peer = bgp_peer_group_peer_lookup(bgp, peer_str);
	if (!peer)
		return NB_ERR_INCONSISTENCY;

	direction = yang_dnode_get_enum(args->dnode, "./direction");

	switch (direction) {
	case 1:
		peer_maximum_prefix_unset(peer, afi, safi);
		break;
	case 2:
		UNSET_FLAG(peer->af_flags[afi][safi], PEER_FLAG_MAX_PREFIX_OUT);
		peer->pmax_out[afi][safi] = 0;
		break;
	}

	return NB_OK;
}
/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_prefix_limit_list_destroy(args);
	}

	return NB_OK;
}

void bgp_peer_group_afi_safi_prefix_limit_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	const struct lyd_node *nbr_dnode;
	const struct lyd_node *nbr_af_dnode;
	const char *af_name;
	afi_t afi;
	safi_t safi;

	nbr_af_dnode = yang_dnode_get_parent(args->dnode, "afi-safi");
	af_name = yang_dnode_get_string(nbr_af_dnode, "./afi-safi-name");
	yang_afi_safi_identity2value(af_name, &afi, &safi);

	nbr_dnode = yang_dnode_get_parent(nbr_af_dnode, "peer-group");
	bgp = nb_running_get_entry(nbr_dnode, NULL, true);
	peer_str = yang_dnode_get_string(nbr_dnode, "./peer-group-name");
	peer = bgp_peer_group_peer_lookup(bgp, peer_str);
	if (!peer)
		return;

	bgp_peer_afi_safi_maximum_prefix_set(args, peer, afi, safi);
}
/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/max-prefixes
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_max_prefixes_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/force-check
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_force_check_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/warning-only
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/restart-timer
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/tr-restart-timer
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/options/tw-warning-only
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/nexthop-self/next-hop-self
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/nexthop-self/next-hop-self-force
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_FORCE_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/private-as/remove-private-as-all
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_private_as_remove_private_as_all_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_ALL,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/private-as/remove-private-as-all-replace
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_private_as_remove_private_as_all_replace_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/private-as/remove-private-as
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_private_as_remove_private_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/private-as/remove-private-as-replace
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_private_as_remove_private_as_replace_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

static int bgp_peer_group_afi_safi_weight_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	const struct lyd_node *nbr_dnode;
	const struct lyd_node *nbr_af_dnode;
	const char *af_name;
	uint16_t weight;
	afi_t afi;
	safi_t safi;
	int ret;

	nbr_af_dnode = yang_dnode_get_parent(args->dnode, "afi-safi");
	af_name = yang_dnode_get_string(nbr_af_dnode, "./afi-safi-name");
	yang_afi_safi_identity2value(af_name, &afi, &safi);

	nbr_dnode = yang_dnode_get_parent(args->dnode, "peer-group");
	bgp = nb_running_get_entry(nbr_dnode, NULL, true);
	peer_str = yang_dnode_get_string(nbr_dnode, "./peer-group-name");
	peer = bgp_peer_group_peer_lookup(bgp, peer_str);

	weight = yang_dnode_get_uint16(args->dnode, NULL);

	ret = peer_weight_set(peer, afi, safi, weight);
	if (bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret) < 0)
		return NB_ERR_INCONSISTENCY;

	return NB_OK;
}

static int
bgp_peer_group_afi_safi_weight_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const char *peer_str;
	struct peer *peer;
	const struct lyd_node *nbr_dnode;
	const struct lyd_node *nbr_af_dnode;
	const char *af_name;
	afi_t afi;
	safi_t safi;
	int ret;

	nbr_af_dnode = yang_dnode_get_parent(args->dnode, "afi-safi");
	af_name = yang_dnode_get_string(nbr_af_dnode, "./afi-safi-name");
	yang_afi_safi_identity2value(af_name, &afi, &safi);
	nbr_dnode = yang_dnode_get_parent(nbr_af_dnode, "peer-group");
	bgp = nb_running_get_entry(nbr_dnode, NULL, true);
	peer_str = yang_dnode_get_string(nbr_dnode, "./peer-group-name");
	peer = bgp_peer_group_peer_lookup(bgp, peer_str);

	ret = peer_weight_unset(peer, afi, safi);
	if (bgp_nb_errmsg_return(args->errmsg, args->errmsg_len, ret) < 0)
		return NB_ERR_INCONSISTENCY;

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/weight/weight-attribute
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_weight_weight_attribute_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_weight_modify(args);

		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_weight_weight_attribute_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_weight_destroy(args);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/route-reflector/route-reflector-client
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_REFLECTOR_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/route-server/route-server-client
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_RSERVER_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/send-community/send-community
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_send_community_send_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/send-community/send-ext-community
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_send_community_send_ext_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_EXT_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/send-community/send-large-community
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_send_community_send_large_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_LARGE_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/soft-reconfiguration
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_SOFT_RECONFIG,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/attr-unchanged/as-path-unchanged
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_AS_PATH_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/attr-unchanged/next-hop-unchanged
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/attr-unchanged/med-unchanged
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_MED_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/orf-capability/orf-send
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_send_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_send_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/orf-capability/orf-receive
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_receive_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_receive_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/orf-capability/orf-both
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_both_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_orf_capability_orf_both_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/filter-config/rmap-import
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_import_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_import_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/filter-config/rmap-export
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_export_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_rmap_export_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/filter-config/plist-import
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_plist_import_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_plist_import_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/filter-config/plist-export
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_plist_export_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_plist_export_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/filter-config/access-list-import
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_access_list_import_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_access_list_import_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/filter-config/access-list-export
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_access_list_export_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_access_list_export_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/filter-config/as-path-filter-list-import
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_as_path_filter_list_import_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_as_path_filter_list_import_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/filter-config/as-path-filter-list-export
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_as_path_filter_list_export_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_as_path_filter_list_export_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/filter-config/unsuppress-map-import
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_unsuppress_map_import_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_unsuppress_map_import_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/filter-config/unsuppress-map-export
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_unsuppress_map_export_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_unsuppress_map_export_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/nexthop-local-unchanged
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_nexthop_local_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/add-paths/path-type
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_add_paths_path_type_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/as-path-options/allow-own-as
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/as-path-options/allow-own-origin-as
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/as-path-options/replace-peer-as
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_AS_OVERRIDE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/default-originate/originate
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_default_originate_originate_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/default-originate/route-map
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_default_originate_route_map_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_default_originate_route_map_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/attr-unchanged/as-path-unchanged
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_AS_PATH_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/attr-unchanged/next-hop-unchanged
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/attr-unchanged/med-unchanged
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_MED_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/orf-capability/orf-send
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_send_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_send_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/orf-capability/orf-receive
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_receive_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_receive_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/orf-capability/orf-both
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_both_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_orf_capability_orf_both_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_prefix_limit_list_destroy(args);
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/max-prefixes
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_max_prefixes_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/force-check
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_force_check_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/warning-only
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/restart-timer
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/tr-restart-timer
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/options/tw-warning-only
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/nexthop-self/next-hop-self
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/nexthop-self/next-hop-self-force
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_FORCE_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/private-as/remove-private-as-all
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_private_as_remove_private_as_all_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_ALL,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/private-as/remove-private-as-all-replace
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_private_as_remove_private_as_all_replace_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/private-as/remove-private-as
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_private_as_remove_private_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/private-as/remove-private-as-replace
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_private_as_remove_private_as_replace_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/route-reflector/route-reflector-client
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_REFLECTOR_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/route-server/route-server-client
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_RSERVER_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/send-community/send-community
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_send_community_send_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/send-community/send-ext-community
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_send_community_send_ext_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_EXT_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/send-community/send-large-community
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_send_community_send_large_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_LARGE_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/soft-reconfiguration
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_SOFT_RECONFIG,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/weight/weight-attribute
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_weight_weight_attribute_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_weight_modify(args);

		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_weight_weight_attribute_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_weight_destroy(args);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/add-paths/path-type
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_add_paths_path_type_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/as-path-options/allow-own-as
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/as-path-options/allow-own-origin-as
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/as-path-options/replace-peer-as
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_AS_OVERRIDE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/default-originate/originate
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_default_originate_originate_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/default-originate/route-map
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_default_originate_route_map_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_default_originate_route_map_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/attr-unchanged/as-path-unchanged
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_AS_PATH_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/attr-unchanged/next-hop-unchanged
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/attr-unchanged/med-unchanged
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_MED_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/orf-capability/orf-send
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_send_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_send_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/orf-capability/orf-receive
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_receive_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_receive_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/orf-capability/orf-both
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_both_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_orf_capability_orf_both_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_prefix_limit_list_destroy(args);
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/max-prefixes
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_max_prefixes_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/force-check
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_force_check_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/warning-only
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/restart-timer
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/shutdown-threshold-pct
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/tr-restart-timer
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/options/tw-warning-only
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/nexthop-self/next-hop-self
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/nexthop-self/next-hop-self-force
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_FORCE_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/private-as/remove-private-as-all
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_private_as_remove_private_as_all_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_ALL,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/private-as/remove-private-as-all-replace
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_private_as_remove_private_as_all_replace_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/private-as/remove-private-as
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_private_as_remove_private_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/private-as/remove-private-as-replace
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_private_as_remove_private_as_replace_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/route-reflector/route-reflector-client
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_REFLECTOR_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/route-server/route-server-client
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_RSERVER_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/send-community/send-community
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_send_community_send_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/send-community/send-ext-community
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_send_community_send_ext_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_EXT_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/send-community/send-large-community
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_send_community_send_large_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_LARGE_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/soft-reconfiguration
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_SOFT_RECONFIG,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/weight/weight-attribute
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_weight_weight_attribute_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_weight_modify(args);

		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_weight_weight_attribute_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_weight_destroy(args);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/add-paths/path-type
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_add_paths_path_type_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/as-path-options/allow-own-as
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/as-path-options/allow-own-origin-as
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/as-path-options/replace-peer-as
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_AS_OVERRIDE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/default-originate/originate
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_default_originate_originate_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/default-originate/route-map
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_default_originate_route_map_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_default_originate_route_map_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/attr-unchanged/as-path-unchanged
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_AS_PATH_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/attr-unchanged/next-hop-unchanged
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/attr-unchanged/med-unchanged
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_MED_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/orf-capability/orf-send
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_send_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_send_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/orf-capability/orf-receive
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_receive_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_receive_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/orf-capability/orf-both
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_both_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_orf_capability_orf_both_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_prefix_limit_list_destroy(args);
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/max-prefixes
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_max_prefixes_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/force-check
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_force_check_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/warning-only
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/restart-timer
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/shutdown-threshold-pct
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/tr-restart-timer
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/options/tw-warning-only
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/nexthop-self/next-hop-self
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/nexthop-self/next-hop-self-force
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_FORCE_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/private-as/remove-private-as-all
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_private_as_remove_private_as_all_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_ALL,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/private-as/remove-private-as-all-replace
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_private_as_remove_private_as_all_replace_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/private-as/remove-private-as
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_private_as_remove_private_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/private-as/remove-private-as-replace
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_private_as_remove_private_as_replace_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/route-reflector/route-reflector-client
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_REFLECTOR_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/route-server/route-server-client
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_RSERVER_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/send-community/send-community
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_send_community_send_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/send-community/send-ext-community
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_send_community_send_ext_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_EXT_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/send-community/send-large-community
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_send_community_send_large_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_LARGE_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/soft-reconfiguration
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_SOFT_RECONFIG,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/weight/weight-attribute
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_weight_weight_attribute_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_weight_modify(args);

		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_weight_weight_attribute_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_weight_destroy(args);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/add-paths/path-type
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_add_paths_path_type_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/as-path-options/allow-own-as
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/as-path-options/allow-own-origin-as
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/as-path-options/replace-peer-as
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_AS_OVERRIDE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/default-originate/originate
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_default_originate_originate_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/default-originate/route-map
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_default_originate_route_map_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_default_originate_route_map_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/attr-unchanged/as-path-unchanged
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_AS_PATH_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/attr-unchanged/next-hop-unchanged
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/attr-unchanged/med-unchanged
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_MED_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/orf-capability/orf-send
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_send_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_send_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/orf-capability/orf-receive
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_receive_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_receive_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/orf-capability/orf-both
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_both_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_orf_capability_orf_both_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_prefix_limit_list_destroy(args);
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/max-prefixes
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_max_prefixes_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/force-check
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_force_check_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/warning-only
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/restart-timer
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/tr-restart-timer
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/options/tw-warning-only
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/nexthop-self/next-hop-self
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/nexthop-self/next-hop-self-force
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_FORCE_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/private-as/remove-private-as-all
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_private_as_remove_private_as_all_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_ALL,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/private-as/remove-private-as-all-replace
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_private_as_remove_private_as_all_replace_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/private-as/remove-private-as
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_private_as_remove_private_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/private-as/remove-private-as-replace
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_private_as_remove_private_as_replace_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/route-reflector/route-reflector-client
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_REFLECTOR_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/route-server/route-server-client
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_RSERVER_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/send-community/send-community
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_send_community_send_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/send-community/send-ext-community
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_send_community_send_ext_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_EXT_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/send-community/send-large-community
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_send_community_send_large_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_LARGE_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/soft-reconfiguration
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_SOFT_RECONFIG,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/weight/weight-attribute
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_weight_weight_attribute_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_weight_modify(args);

		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_weight_weight_attribute_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_weight_destroy(args);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/add-paths/path-type
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_add_paths_path_type_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/as-path-options/allow-own-as
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/as-path-options/allow-own-origin-as
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/as-path-options/replace-peer-as
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_AS_OVERRIDE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/default-originate/originate
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_default_originate_originate_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/default-originate/route-map
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_default_originate_route_map_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_default_originate_route_map_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/attr-unchanged/as-path-unchanged
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_AS_PATH_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/attr-unchanged/next-hop-unchanged
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/attr-unchanged/med-unchanged
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_MED_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/orf-capability/orf-send
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_send_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_send_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/orf-capability/orf-receive
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_receive_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_receive_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/orf-capability/orf-both
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_both_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_orf_capability_orf_both_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_prefix_limit_list_destroy(args);
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/max-prefixes
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_max_prefixes_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/force-check
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_force_check_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/warning-only
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/restart-timer
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/tr-restart-timer
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/options/tw-warning-only
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/nexthop-self/next-hop-self
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/nexthop-self/next-hop-self-force
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_FORCE_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/private-as/remove-private-as-all
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_private_as_remove_private_as_all_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_ALL,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/private-as/remove-private-as-all-replace
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_private_as_remove_private_as_all_replace_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/private-as/remove-private-as
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_private_as_remove_private_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/private-as/remove-private-as-replace
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_private_as_remove_private_as_replace_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/route-reflector/route-reflector-client
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_REFLECTOR_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/route-server/route-server-client
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_RSERVER_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/send-community/send-community
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_send_community_send_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/send-community/send-ext-community
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_send_community_send_ext_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_EXT_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/send-community/send-large-community
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_send_community_send_large_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_LARGE_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/soft-reconfiguration
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_SOFT_RECONFIG,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/weight/weight-attribute
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_weight_weight_attribute_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_weight_modify(args);

		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_weight_weight_attribute_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_weight_destroy(args);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/add-paths/path-type
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_add_paths_path_type_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/as-path-options/allow-own-as
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/as-path-options/allow-own-origin-as
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/as-path-options/replace-peer-as
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_AS_OVERRIDE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/attr-unchanged/as-path-unchanged
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_AS_PATH_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/attr-unchanged/next-hop-unchanged
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/attr-unchanged/med-unchanged
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_MED_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_prefix_limit_list_destroy(args);
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/max-prefixes
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_max_prefixes_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/force-check
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_force_check_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/warning-only
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/restart-timer
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/tr-restart-timer
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/options/tw-warning-only
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/nexthop-self/next-hop-self
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/nexthop-self/next-hop-self-force
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_FORCE_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/private-as/remove-private-as-all
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_private_as_remove_private_as_all_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_ALL,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/private-as/remove-private-as-all-replace
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_private_as_remove_private_as_all_replace_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/private-as/remove-private-as
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_private_as_remove_private_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/private-as/remove-private-as-replace
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_private_as_remove_private_as_replace_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/route-reflector/route-reflector-client
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_REFLECTOR_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/route-server/route-server-client
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_RSERVER_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/send-community/send-community
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_send_community_send_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/send-community/send-ext-community
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_send_community_send_ext_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_EXT_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/send-community/send-large-community
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_send_community_send_large_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_LARGE_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/soft-reconfiguration
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_SOFT_RECONFIG,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/weight/weight-attribute
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_weight_weight_attribute_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_weight_modify(args);

		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_weight_weight_attribute_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_weight_destroy(args);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/add-paths/path-type
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_add_paths_path_type_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/as-path-options/allow-own-as
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/as-path-options/allow-own-origin-as
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/as-path-options/replace-peer-as
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_AS_OVERRIDE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/attr-unchanged/as-path-unchanged
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_AS_PATH_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/attr-unchanged/next-hop-unchanged
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/attr-unchanged/med-unchanged
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_MED_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_prefix_limit_list_destroy(args);
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/max-prefixes
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_max_prefixes_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/force-check
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_force_check_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/warning-only
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/restart-timer
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/shutdown-threshold-pct
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/tr-shutdown-threshold-pct
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/tr-restart-timer
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/tw-shutdown-threshold-pct
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/options/tw-warning-only
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/nexthop-self/next-hop-self
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/nexthop-self/next-hop-self-force
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_FORCE_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/private-as/remove-private-as-all
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_private_as_remove_private_as_all_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_ALL,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/private-as/remove-private-as-all-replace
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_private_as_remove_private_as_all_replace_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/private-as/remove-private-as
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_private_as_remove_private_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/private-as/remove-private-as-replace
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_private_as_remove_private_as_replace_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/route-reflector/route-reflector-client
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_REFLECTOR_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/route-server/route-server-client
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_RSERVER_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/send-community/send-community
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_send_community_send_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/send-community/send-ext-community
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_send_community_send_ext_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_EXT_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/send-community/send-large-community
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_send_community_send_large_community_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_SEND_LARGE_COMMUNITY,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/soft-reconfiguration
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_SOFT_RECONFIG,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/weight/weight-attribute
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_weight_weight_attribute_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_weight_modify(args);

		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_weight_weight_attribute_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_weight_destroy(args);

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/as-path-options/allow-own-as
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_as_path_options_allow_own_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_as_path_options_allow_own_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/as-path-options/allow-own-origin-as
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_as_path_options_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_as_path_options_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/as-path-options/replace-peer-as
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_as_path_options_replace_peer_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_AS_OVERRIDE,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/attr-unchanged/as-path-unchanged
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_attr_unchanged_as_path_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_AS_PATH_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/attr-unchanged/next-hop-unchanged
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_attr_unchanged_next_hop_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/attr-unchanged/med-unchanged
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_attr_unchanged_med_unchanged_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_MED_UNCHANGED,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/nexthop-self/next-hop-self
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_nexthop_self_next_hop_self_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/nexthop-self/next-hop-self-force
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_nexthop_self_next_hop_self_force_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_FORCE_NEXTHOP_SELF,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/route-reflector/route-reflector-client
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_REFLECTOR_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/route-server/route-server-client
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_RSERVER_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l2vpn-evpn/soft-reconfiguration
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l2vpn_evpn_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_SOFT_RECONFIG,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-flowspec/route-reflector/route-reflector-client
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_flowspec_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_REFLECTOR_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-flowspec/route-server/route-server-client
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_flowspec_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_RSERVER_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-flowspec/soft-reconfiguration
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_flowspec_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_SOFT_RECONFIG,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-flowspec/route-reflector/route-reflector-client
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_flowspec_route_reflector_route_reflector_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_REFLECTOR_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-flowspec/route-server/route-server-client
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_flowspec_route_server_route_server_client_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_RSERVER_CLIENT,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-flowspec/soft-reconfiguration
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_flowspec_soft_reconfiguration_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_peer_group_afi_safi_flag_modify(
			args, PEER_FLAG_SOFT_RECONFIG,
			yang_dnode_get_bool(args->dnode, NULL));

		break;
	}

	return NB_OK;
}
