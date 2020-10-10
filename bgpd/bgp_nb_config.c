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


static int bgp_lookup_by_as_name_type(struct bgp **bgp_val, as_t *as,
				      const char *name,
				      enum bgp_instance_type inst_type)
{
	struct bgp *bgp;

	if (name)
		bgp = bgp_lookup_by_name(name);
	else
		bgp = bgp_get_default();

	if (bgp) {
		if (bgp->as != *as) {
			*as = bgp->as;
			return BGP_ERR_INSTANCE_MISMATCH;
		}
		if (bgp->inst_type != inst_type)
			return BGP_ERR_INSTANCE_MISMATCH;
		*bgp_val = bgp;
	} else {
		*bgp_val = NULL;
	}

	return BGP_SUCCESS;
}

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

		bgp_vpn_leak_unimport(bgp);
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
			THREAD_TIMER_OFF(bgp->t_maxmed_onstartup);
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

		bgp_timers_set(bgp, keepalive, holdtime,
			       DFLT_BGP_CONNECT_RETRY);

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

		bgp_timers_set(bgp, keepalive, holdtime,
			       DFLT_BGP_CONNECT_RETRY);

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
	switch (args->event) {
	case NB_EV_VALIDATE:
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

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor
 */
int bgp_neighbors_neighbor_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_local_interface_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_local_port_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_peer_group_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_password_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_ttl_security_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_description_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_update_source_ip_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_update_source_interface_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_ebgp_multihop_enabled_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_ebgp_multihop_multihop_ttl_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_timers_advertise_interval_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_timers_connect_time_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor
 */
int bgp_neighbors_unnumbered_neighbor_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_peer_group_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_password_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_ttl_security_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_description_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_update_source_ip_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_update_source_interface_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_ebgp_multihop_enabled_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_ebgp_multihop_multihop_ttl_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_timers_advertise_interval_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_timers_connect_time_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group
 */
int bgp_peer_groups_peer_group_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_password_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_ttl_security_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_description_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_update_source_ip_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_update_source_interface_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_ebgp_multihop_enabled_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_ebgp_multihop_multihop_ttl_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_timers_advertise_interval_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_timers_connect_time_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/network-config
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_network_config_create(
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

int bgp_global_afi_safis_afi_safi_ipv4_unicast_network_config_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/network-config/label-index
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_network_config_label_index_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_unicast_network_config_label_index_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/network-config/rmap-policy-export
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_network_config_rmap_policy_export_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_unicast_network_config_rmap_policy_export_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

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
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
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

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/route-flap-dampening/enable
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_route_flap_dampening_enable_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
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

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/use-multiple-paths/ebgp/maximum-paths
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_use_multiple_paths_ebgp_maximum_paths_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/use-multiple-paths/ibgp/maximum-paths
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_use_multiple_paths_ibgp_maximum_paths_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/admin-distance/external
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_admin_distance_external_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_unicast_admin_distance_external_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/admin-distance/internal
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_admin_distance_internal_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_unicast_admin_distance_internal_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/admin-distance/local
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_admin_distance_local_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_unicast_admin_distance_local_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

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

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/rd
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_rd_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
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

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/nexthop
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_nexthop_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-unicast/vpn-config/import-vrf-list
 */
int bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_import_vrf_list_create(
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

int bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_import_vrf_list_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_unicast_vpn_config_rmap_import_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv6_unicast_network_config_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/network-config/label-index
 */
int bgp_global_afi_safis_afi_safi_ipv6_unicast_network_config_label_index_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

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
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
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
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/use-multiple-paths/ebgp/maximum-paths
 */
int bgp_global_afi_safis_afi_safi_ipv6_unicast_use_multiple_paths_ebgp_maximum_paths_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/admin-distance/external
 */
int bgp_global_afi_safis_afi_safi_ipv6_unicast_admin_distance_external_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv6_unicast_admin_distance_external_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/admin-distance/internal
 */
int bgp_global_afi_safis_afi_safi_ipv6_unicast_admin_distance_internal_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv6_unicast_admin_distance_internal_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-unicast/admin-distance/local
 */
int bgp_global_afi_safis_afi_safi_ipv6_unicast_admin_distance_local_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv6_unicast_admin_distance_local_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
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
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-labeled-unicast/use-multiple-paths/ebgp/maximum-paths
 */
int bgp_global_afi_safis_afi_safi_ipv6_labeled_unicast_use_multiple_paths_ebgp_maximum_paths_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
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
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/network-config
 */
int bgp_global_afi_safis_afi_safi_ipv4_multicast_network_config_create(
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

int bgp_global_afi_safis_afi_safi_ipv4_multicast_network_config_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/admin-distance/external
 */
int bgp_global_afi_safis_afi_safi_ipv4_multicast_admin_distance_external_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_multicast_admin_distance_external_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/admin-distance/internal
 */
int bgp_global_afi_safis_afi_safi_ipv4_multicast_admin_distance_internal_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_multicast_admin_distance_internal_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv4-multicast/admin-distance/local
 */
int bgp_global_afi_safis_afi_safi_ipv4_multicast_admin_distance_local_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv4_multicast_admin_distance_local_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

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
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv6_multicast_network_config_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/admin-distance/external
 */
int bgp_global_afi_safis_afi_safi_ipv6_multicast_admin_distance_external_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv6_multicast_admin_distance_external_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/admin-distance/internal
 */
int bgp_global_afi_safis_afi_safi_ipv6_multicast_admin_distance_internal_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv6_multicast_admin_distance_internal_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/global/afi-safis/afi-safi/ipv6-multicast/admin-distance/local
 */
int bgp_global_afi_safis_afi_safi_ipv6_multicast_admin_distance_local_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_global_afi_safis_afi_safi_ipv6_multicast_admin_distance_local_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

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
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/default-originate-options/send-default-route
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_default_originate_options_send_default_route_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/default-originate-options/rmap-policy-export
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_default_originate_options_rmap_policy_export_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_default_originate_options_rmap_policy_export_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
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
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/prefix-limit-options/warning-only
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/prefix-limit-options/restart-timer
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/prefix-limit-options/shutdown-threshold-pct
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/prefix-limit-options/tr-shutdown-threshold-pct
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/prefix-limit-options/tr-restart-timer
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/prefix-limit-options/tw-shutdown-threshold-pct
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/prefix-limit-options/tw-warning-only
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/unsupress-map-import
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_unsupress_map_import_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_unsupress_map_import_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/unsupress-map-export
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_unsupress_map_export_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_unsupress_map_export_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
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
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/prefix-limit-options/warning-only
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/prefix-limit-options/restart-timer
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/prefix-limit-options/shutdown-threshold-pct
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/prefix-limit-options/tr-shutdown-threshold-pct
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/prefix-limit-options/tr-restart-timer
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/prefix-limit-options/tw-shutdown-threshold-pct
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/prefix-limit-options/tw-warning-only
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
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
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/prefix-limit-options/warning-only
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_prefix_limit_options_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_prefix_limit_options_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/prefix-limit-options/restart-timer
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_prefix_limit_options_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_prefix_limit_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/prefix-limit-options/shutdown-threshold-pct
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_prefix_limit_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_prefix_limit_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/prefix-limit-options/tr-shutdown-threshold-pct
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_prefix_limit_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_prefix_limit_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/prefix-limit-options/tr-restart-timer
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_prefix_limit_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_prefix_limit_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/prefix-limit-options/tw-shutdown-threshold-pct
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_prefix_limit_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_prefix_limit_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/prefix-limit-options/tw-warning-only
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_prefix_limit_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_prefix_limit_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
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
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/prefix-limit-options/warning-only
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_prefix_limit_options_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_prefix_limit_options_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/prefix-limit-options/restart-timer
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_prefix_limit_options_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_prefix_limit_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/prefix-limit-options/shutdown-threshold-pct
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_prefix_limit_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_prefix_limit_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/prefix-limit-options/tr-shutdown-threshold-pct
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_prefix_limit_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_prefix_limit_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/prefix-limit-options/tr-restart-timer
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_prefix_limit_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_prefix_limit_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/prefix-limit-options/tw-shutdown-threshold-pct
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_prefix_limit_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_prefix_limit_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/prefix-limit-options/tw-warning-only
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_prefix_limit_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_prefix_limit_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
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
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/prefix-limit-options/warning-only
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/prefix-limit-options/restart-timer
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/prefix-limit-options/shutdown-threshold-pct
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/prefix-limit-options/tr-shutdown-threshold-pct
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/prefix-limit-options/tr-restart-timer
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/prefix-limit-options/tw-shutdown-threshold-pct
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/prefix-limit-options/tw-warning-only
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
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
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/prefix-limit-options/warning-only
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/prefix-limit-options/restart-timer
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/prefix-limit-options/shutdown-threshold-pct
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/prefix-limit-options/tr-shutdown-threshold-pct
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/prefix-limit-options/tr-restart-timer
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/prefix-limit-options/tw-shutdown-threshold-pct
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/prefix-limit-options/tw-warning-only
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
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
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/prefix-limit-options/warning-only
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/prefix-limit-options/restart-timer
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/prefix-limit-options/shutdown-threshold-pct
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/prefix-limit-options/tr-shutdown-threshold-pct
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/prefix-limit-options/tr-restart-timer
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/prefix-limit-options/tw-shutdown-threshold-pct
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/prefix-limit-options/tw-warning-only
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
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
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/prefix-limit-options/warning-only
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/prefix-limit-options/restart-timer
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/prefix-limit-options/shutdown-threshold-pct
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/prefix-limit-options/tr-shutdown-threshold-pct
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/prefix-limit-options/tr-restart-timer
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/prefix-limit-options/tw-shutdown-threshold-pct
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/prefix-limit-options/tw-warning-only
 */
int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

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
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/default-originate-options/send-default-route
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_default_originate_options_send_default_route_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/default-originate-options/rmap-policy-export
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_default_originate_options_rmap_policy_export_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_default_originate_options_rmap_policy_export_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
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
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/prefix-limit-options/warning-only
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/prefix-limit-options/restart-timer
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/prefix-limit-options/shutdown-threshold-pct
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/prefix-limit-options/tr-shutdown-threshold-pct
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/prefix-limit-options/tr-restart-timer
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/prefix-limit-options/tw-shutdown-threshold-pct
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/prefix-limit-options/tw-warning-only
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/unsupress-map-import
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_unsupress_map_import_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_unsupress_map_import_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-unicast/filter-config/unsupress-map-export
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_unsupress_map_export_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_unicast_filter_config_unsupress_map_export_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
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
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/prefix-limit-options/warning-only
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/prefix-limit-options/restart-timer
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/prefix-limit-options/shutdown-threshold-pct
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/prefix-limit-options/tr-shutdown-threshold-pct
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/prefix-limit-options/tr-restart-timer
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/prefix-limit-options/tw-shutdown-threshold-pct
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/prefix-limit-options/tw-warning-only
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
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
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/prefix-limit-options/warning-only
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_prefix_limit_options_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_prefix_limit_options_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/prefix-limit-options/restart-timer
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_prefix_limit_options_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_prefix_limit_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/prefix-limit-options/shutdown-threshold-pct
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_prefix_limit_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_prefix_limit_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/prefix-limit-options/tr-shutdown-threshold-pct
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_prefix_limit_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_prefix_limit_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/prefix-limit-options/tr-restart-timer
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_prefix_limit_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_prefix_limit_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/prefix-limit-options/tw-shutdown-threshold-pct
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_prefix_limit_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_prefix_limit_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/prefix-limit-options/tw-warning-only
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_prefix_limit_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_prefix_limit_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
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
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/prefix-limit-options/warning-only
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_prefix_limit_options_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_prefix_limit_options_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/prefix-limit-options/restart-timer
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_prefix_limit_options_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_prefix_limit_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/prefix-limit-options/shutdown-threshold-pct
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_prefix_limit_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_prefix_limit_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/prefix-limit-options/tr-shutdown-threshold-pct
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_prefix_limit_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_prefix_limit_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/prefix-limit-options/tr-restart-timer
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_prefix_limit_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_prefix_limit_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/prefix-limit-options/tw-shutdown-threshold-pct
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_prefix_limit_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_prefix_limit_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/prefix-limit-options/tw-warning-only
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_prefix_limit_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_prefix_limit_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
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
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/prefix-limit-options/warning-only
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/prefix-limit-options/restart-timer
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/prefix-limit-options/shutdown-threshold-pct
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/prefix-limit-options/tr-shutdown-threshold-pct
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/prefix-limit-options/tr-restart-timer
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/prefix-limit-options/tw-shutdown-threshold-pct
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/prefix-limit-options/tw-warning-only
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
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
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/prefix-limit-options/warning-only
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/prefix-limit-options/restart-timer
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/prefix-limit-options/shutdown-threshold-pct
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/prefix-limit-options/tr-shutdown-threshold-pct
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/prefix-limit-options/tr-restart-timer
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/prefix-limit-options/tw-shutdown-threshold-pct
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/prefix-limit-options/tw-warning-only
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
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
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/prefix-limit-options/warning-only
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/prefix-limit-options/restart-timer
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/prefix-limit-options/shutdown-threshold-pct
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/prefix-limit-options/tr-shutdown-threshold-pct
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/prefix-limit-options/tr-restart-timer
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/prefix-limit-options/tw-shutdown-threshold-pct
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/prefix-limit-options/tw-warning-only
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
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
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/prefix-limit-options/warning-only
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/prefix-limit-options/restart-timer
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/prefix-limit-options/shutdown-threshold-pct
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/prefix-limit-options/tr-shutdown-threshold-pct
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/prefix-limit-options/tr-restart-timer
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/prefix-limit-options/tw-shutdown-threshold-pct
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/neighbors/unnumbered-neighbor/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/prefix-limit-options/tw-warning-only
 */
int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_neighbors_unnumbered_neighbor_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

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
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/default-originate-options/send-default-route
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_default_originate_options_send_default_route_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/default-originate-options/rmap-policy-export
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_default_originate_options_rmap_policy_export_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_default_originate_options_rmap_policy_export_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
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
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/prefix-limit-options/warning-only
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/prefix-limit-options/restart-timer
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/prefix-limit-options/shutdown-threshold-pct
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/prefix-limit-options/tr-shutdown-threshold-pct
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/prefix-limit-options/tr-restart-timer
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/prefix-limit-options/tw-shutdown-threshold-pct
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/prefix-limit/direction-list/prefix-limit-options/tw-warning-only
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/filter-config/unsupress-map-import
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_unsupress_map_import_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_unsupress_map_import_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-unicast/filter-config/unsupress-map-export
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_unsupress_map_export_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_unicast_filter_config_unsupress_map_export_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
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
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/prefix-limit-options/warning-only
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/prefix-limit-options/restart-timer
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/prefix-limit-options/shutdown-threshold-pct
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/prefix-limit-options/tr-shutdown-threshold-pct
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/prefix-limit-options/tr-restart-timer
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/prefix-limit-options/tw-shutdown-threshold-pct
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-unicast/prefix-limit/direction-list/prefix-limit-options/tw-warning-only
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
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
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/prefix-limit-options/warning-only
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_prefix_limit_options_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_prefix_limit_options_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/prefix-limit-options/restart-timer
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_prefix_limit_options_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_prefix_limit_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/prefix-limit-options/shutdown-threshold-pct
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_prefix_limit_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_prefix_limit_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/prefix-limit-options/tr-shutdown-threshold-pct
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_prefix_limit_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_prefix_limit_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/prefix-limit-options/tr-restart-timer
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_prefix_limit_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_prefix_limit_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/prefix-limit-options/tw-shutdown-threshold-pct
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_prefix_limit_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_prefix_limit_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-multicast/prefix-limit/direction-list/prefix-limit-options/tw-warning-only
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_prefix_limit_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_multicast_prefix_limit_direction_list_prefix_limit_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
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
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/prefix-limit-options/warning-only
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_prefix_limit_options_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_prefix_limit_options_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/prefix-limit-options/restart-timer
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_prefix_limit_options_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_prefix_limit_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/prefix-limit-options/shutdown-threshold-pct
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_prefix_limit_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_prefix_limit_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/prefix-limit-options/tr-shutdown-threshold-pct
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_prefix_limit_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_prefix_limit_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/prefix-limit-options/tr-restart-timer
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_prefix_limit_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_prefix_limit_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/prefix-limit-options/tw-shutdown-threshold-pct
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_prefix_limit_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_prefix_limit_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-multicast/prefix-limit/direction-list/prefix-limit-options/tw-warning-only
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_prefix_limit_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_multicast_prefix_limit_direction_list_prefix_limit_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
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
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/prefix-limit-options/warning-only
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/prefix-limit-options/restart-timer
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/prefix-limit-options/shutdown-threshold-pct
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/prefix-limit-options/tr-shutdown-threshold-pct
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/prefix-limit-options/tr-restart-timer
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/prefix-limit-options/tw-shutdown-threshold-pct
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv4-labeled-unicast/prefix-limit/direction-list/prefix-limit-options/tw-warning-only
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv4_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
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
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/prefix-limit-options/warning-only
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/prefix-limit-options/restart-timer
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/prefix-limit-options/shutdown-threshold-pct
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/prefix-limit-options/tr-shutdown-threshold-pct
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/prefix-limit-options/tr-restart-timer
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/prefix-limit-options/tw-shutdown-threshold-pct
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/ipv6-labeled-unicast/prefix-limit/direction-list/prefix-limit-options/tw-warning-only
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_ipv6_labeled_unicast_prefix_limit_direction_list_prefix_limit_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
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
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/prefix-limit-options/warning-only
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/prefix-limit-options/restart-timer
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/prefix-limit-options/shutdown-threshold-pct
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/prefix-limit-options/tr-shutdown-threshold-pct
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/prefix-limit-options/tr-restart-timer
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/prefix-limit-options/tw-shutdown-threshold-pct
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv4-unicast/prefix-limit/direction-list/prefix-limit-options/tw-warning-only
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv4_unicast_prefix_limit_direction_list_prefix_limit_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
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
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/prefix-limit-options/warning-only
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/prefix-limit-options/restart-timer
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/prefix-limit-options/shutdown-threshold-pct
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/prefix-limit-options/tr-shutdown-threshold-pct
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_tr_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_tr_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/prefix-limit-options/tr-restart-timer
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_tr_restart_timer_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_tr_restart_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/prefix-limit-options/tw-shutdown-threshold-pct
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_tw_shutdown_threshold_pct_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_tw_shutdown_threshold_pct_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/peer-groups/peer-group/afi-safis/afi-safi/l3vpn-ipv6-unicast/prefix-limit/direction-list/prefix-limit-options/tw-warning-only
 */
int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_tw_warning_only_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int bgp_peer_groups_peer_group_afi_safis_afi_safi_l3vpn_ipv6_unicast_prefix_limit_direction_list_prefix_limit_options_tw_warning_only_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
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
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}
