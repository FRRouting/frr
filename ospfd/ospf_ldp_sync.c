// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * ospf_ldp_sync.c: OSPF LDP-IGP Sync  handling routines
 * Copyright (C) 2020 Volta Networks, Inc.
 */

#include <zebra.h>
#include <string.h>

#include "monotime.h"
#include "memory.h"
#include "frrevent.h"
#include "prefix.h"
#include "table.h"
#include "vty.h"
#include "command.h"
#include "plist.h"
#include "log.h"
#include "zclient.h"
#include <lib/json.h>
#include "defaults.h"
#include "ldp_sync.h"

#include "ospfd.h"
#include "ospf_interface.h"
#include "ospf_vty.h"
#include "ospf_ldp_sync.h"
#include "ospf_dump.h"
#include "ospf_ism.h"

extern struct zclient *zclient;

/*
 * LDP-SYNC msg between IGP and LDP
 */
int ospf_ldp_sync_state_update(struct ldp_igp_sync_if_state state)
{
	struct ospf *ospf;
	struct interface *ifp;

	/* if ospf is not enabled or LDP-SYNC is not configured ignore */
	ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
	if (ospf == NULL ||
	    !CHECK_FLAG(ospf->ldp_sync_cmd.flags, LDP_SYNC_FLAG_ENABLE))
		return 0;

	/* received ldp-sync interface state from LDP */
	ifp = if_lookup_by_index(state.ifindex, VRF_DEFAULT);
	if (ifp == NULL || if_is_loopback(ifp))
		return 0;

	ols_debug("%s: rcvd %s from LDP if %s", __func__,
		  state.sync_start ? "sync-start" : "sync-complete", ifp->name);
	if (state.sync_start)
		ospf_ldp_sync_if_start(ifp, false);
	else
		ospf_ldp_sync_if_complete(ifp);

	return 0;
}

int ospf_ldp_sync_announce_update(struct ldp_igp_sync_announce announce)
{
	struct ospf *ospf;
	struct vrf *vrf;
	struct interface *ifp;

	/* if ospf is not enabled or LDP-SYNC is not configured ignore */
	ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
	if (ospf == NULL ||
	    !CHECK_FLAG(ospf->ldp_sync_cmd.flags, LDP_SYNC_FLAG_ENABLE))
		return 0;

	if (announce.proto != ZEBRA_ROUTE_LDP)
		return 0;

	ols_debug("%s: rcvd announce from LDP", __func__);

	/* LDP just started up:
	 *  set cost to LSInfinity
	 *  send request to LDP for LDP-SYNC state for each interface
	 */
	vrf = vrf_lookup_by_id(ospf->vrf_id);
	FOR_ALL_INTERFACES (vrf, ifp)
		ospf_ldp_sync_if_start(ifp, true);

	return 0;
}

void ospf_ldp_sync_state_req_msg(struct interface *ifp)
{
	struct ldp_igp_sync_if_state_req request;

	ols_debug("%s: send state request to LDP for %s", __func__, ifp->name);

	memset(&request, 0, sizeof(request));
	strlcpy(request.name, ifp->name, sizeof(ifp->name));
	request.proto = LDP_IGP_SYNC_IF_STATE_REQUEST;
	request.ifindex = ifp->ifindex;

	zclient_send_opaque(zclient, LDP_IGP_SYNC_IF_STATE_REQUEST,
		(uint8_t *)&request, sizeof(request));
}

/*
 * LDP-SYNC general interface routines
 */
void ospf_ldp_sync_if_init(struct ospf_interface *oi)
{
	struct ospf_if_params *params;
	struct ldp_sync_info *ldp_sync_info;
	struct interface *ifp = oi->ifp;

	/* called when OSPF is configured on an interface:
	 *  if LDP-IGP Sync is configured globally set state
	 *  if ptop interface inform LDP LDP-SYNC is enabled
	 */
	if (if_is_loopback(ifp) || (ifp->vrf->vrf_id != VRF_DEFAULT)
	    || !(CHECK_FLAG(oi->ospf->ldp_sync_cmd.flags,
			    LDP_SYNC_FLAG_ENABLE)))
		return;

	ols_debug("%s: init if %s", __func__, ifp->name);
	params = IF_DEF_PARAMS(ifp);
	if (params->ldp_sync_info == NULL)
		params->ldp_sync_info = ldp_sync_info_create();

	ldp_sync_info = params->ldp_sync_info;

	/* specified on interface overrides global config. */
	if (!CHECK_FLAG(ldp_sync_info->flags, LDP_SYNC_FLAG_HOLDDOWN))
		ldp_sync_info->holddown = oi->ospf->ldp_sync_cmd.holddown;

	if (!CHECK_FLAG(ldp_sync_info->flags, LDP_SYNC_FLAG_IF_CONFIG))
		ldp_sync_info->enabled = LDP_IGP_SYNC_ENABLED;

	if ((params->type == OSPF_IFTYPE_POINTOPOINT ||
	     if_is_pointopoint(ifp)) &&
	    ldp_sync_info->enabled == LDP_IGP_SYNC_ENABLED)
		ldp_sync_info->state = LDP_IGP_SYNC_STATE_REQUIRED_NOT_UP;
}

void ospf_ldp_sync_if_start(struct interface *ifp, bool send_state_req)
{
	struct ospf_if_params *params;
	struct ldp_sync_info *ldp_sync_info;

	if (if_is_loopback(ifp))
		return;

	params = IF_DEF_PARAMS(ifp);
	ldp_sync_info = params->ldp_sync_info;

	/* Start LDP-SYNC on this interface:
	 *  set cost of interface to LSInfinity so traffic will use different
	 *  interface until LDP has learned all labels from peer
	 *  start holddown timer if configured
	 *  send msg to LDP to get LDP-SYNC state
	 */
	if (ldp_sync_info &&
	    ldp_sync_info->enabled == LDP_IGP_SYNC_ENABLED &&
	    ldp_sync_info->state != LDP_IGP_SYNC_STATE_NOT_REQUIRED) {
		ols_debug("%s: start on if %s state: %s", __func__, ifp->name,
			  "Holding down until Sync");
		ldp_sync_info->state = LDP_IGP_SYNC_STATE_REQUIRED_NOT_UP;
		ospf_if_recalculate_output_cost(ifp);
		ospf_ldp_sync_holddown_timer_add(ifp);

		if (send_state_req)
			ospf_ldp_sync_state_req_msg(ifp);
	}
}

void ospf_ldp_sync_if_complete(struct interface *ifp)
{
	struct ospf_if_params *params;
	struct ldp_sync_info *ldp_sync_info;

	if (if_is_loopback(ifp))
		return;

	params = IF_DEF_PARAMS(ifp);
	ldp_sync_info = params->ldp_sync_info;

	/* received sync-complete from LDP:
	 *  set state to up
	 *  stop timer
	 *  restore interface cost to original value
	 */
	if (ldp_sync_info && ldp_sync_info->enabled == LDP_IGP_SYNC_ENABLED) {
		if (ldp_sync_info->state == LDP_IGP_SYNC_STATE_REQUIRED_NOT_UP)
			ldp_sync_info->state = LDP_IGP_SYNC_STATE_REQUIRED_UP;
		EVENT_OFF(ldp_sync_info->t_holddown);
		ospf_if_recalculate_output_cost(ifp);
	}
}

void ospf_ldp_sync_handle_client_close(struct zapi_client_close_info *info)
{
	struct ospf *ospf;
	struct vrf *vrf;
	struct interface *ifp;

	/* if ospf is not enabled or LDP-SYNC is not configured ignore */
	ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
	if (ospf == NULL
	    || !CHECK_FLAG(ospf->ldp_sync_cmd.flags, LDP_SYNC_FLAG_ENABLE))
		return;

	/* Check if the LDP main client session closed */
	if (info->proto != ZEBRA_ROUTE_LDP || info->session_id == 0)
		return;

	/* Handle the zebra notification that the LDP client session closed.
	 *  set cost to LSInfinity
	 *  send request to LDP for LDP-SYNC state for each interface
	 */
	zlog_err("%s: LDP down", __func__);

	vrf = vrf_lookup_by_id(ospf->vrf_id);
	FOR_ALL_INTERFACES (vrf, ifp)
		ospf_ldp_sync_ldp_fail(ifp);
}

void ospf_ldp_sync_ldp_fail(struct interface *ifp)
{
	struct ospf_if_params *params;
	struct ldp_sync_info *ldp_sync_info;

	if (if_is_loopback(ifp))
		return;

	params = IF_DEF_PARAMS(ifp);
	ldp_sync_info = params->ldp_sync_info;

	/* LDP client close detected:
	 *  stop holddown timer
	 *  set cost of interface to LSInfinity so traffic will use different
	 *  interface until LDP has learned all labels from peer
	 */
	if (ldp_sync_info &&
	    ldp_sync_info->enabled == LDP_IGP_SYNC_ENABLED &&
	    ldp_sync_info->state != LDP_IGP_SYNC_STATE_NOT_REQUIRED) {
		EVENT_OFF(ldp_sync_info->t_holddown);
		ldp_sync_info->state = LDP_IGP_SYNC_STATE_REQUIRED_NOT_UP;
		ospf_if_recalculate_output_cost(ifp);
	}
}

void ospf_ldp_sync_if_down(struct interface *ifp)
{
	struct ospf_if_params *params;
	struct ldp_sync_info *ldp_sync_info;

	if (if_is_loopback(ifp))
		return;

	params = IF_DEF_PARAMS(ifp);
	ldp_sync_info = params->ldp_sync_info;

	if (ldp_sync_if_down(ldp_sync_info) == false)
		return;

	ols_debug("%s: down on if %s", __func__, ifp->name);

	/* Interface down:
	 *  can occur from a link down or changing config
	 *  ospf network type change interface is brought down/up
	 */
	switch (ldp_sync_info->state) {
	case LDP_IGP_SYNC_STATE_REQUIRED_NOT_UP:
	case LDP_IGP_SYNC_STATE_REQUIRED_UP:
		if (params->type != OSPF_IFTYPE_POINTOPOINT &&
		    !if_is_pointopoint(ifp))
			/* LDP-SYNC not able to run on non-ptop interface */
			ldp_sync_info->state = LDP_IGP_SYNC_STATE_NOT_REQUIRED;
		break;
	case LDP_IGP_SYNC_STATE_NOT_REQUIRED:
		if (params->type == OSPF_IFTYPE_POINTOPOINT ||
		    if_is_pointopoint(ifp))
			/* LDP-SYNC is able to run on ptop interface */
			ldp_sync_info->state =
				LDP_IGP_SYNC_STATE_REQUIRED_NOT_UP;
		break;
	default:
		break;
	}
}

void ospf_ldp_sync_if_remove(struct interface *ifp, bool remove)
{
	struct ospf_if_params *params;
	struct ldp_sync_info *ldp_sync_info;

	params = IF_DEF_PARAMS(ifp);
	if (params->ldp_sync_info == NULL)
		return;

	ldp_sync_info = params->ldp_sync_info;

	/* Stop LDP-SYNC on this interface:
	 *  if holddown timer is running stop it
	 *  delete ldp instance on interface
	 *  restore cost
	 */
	ols_debug("%s: Removed from if %s", __func__, ifp->name);

	EVENT_OFF(ldp_sync_info->t_holddown);

	ldp_sync_info->state = LDP_IGP_SYNC_STATE_NOT_REQUIRED;
	ospf_if_recalculate_output_cost(ifp);
	if (!CHECK_FLAG(ldp_sync_info->flags, LDP_SYNC_FLAG_IF_CONFIG))
		ldp_sync_info->enabled = LDP_IGP_SYNC_DEFAULT;
	if (remove) {
		ldp_sync_info_free(&ldp_sync_info);
		params->ldp_sync_info = NULL;
	}
}

static int ospf_ldp_sync_ism_change(struct ospf_interface *oi, int state,
				    int old_state)
{
	/* Terminal state or regression */
	switch (state) {
	case ISM_PointToPoint:
		/* If LDP-SYNC is configure on interface then start */
		ospf_ldp_sync_if_start(oi->ifp, true);
		break;
	case ISM_Down:
		/* If LDP-SYNC is configure on this interface then stop it */
		ospf_ldp_sync_if_down(oi->ifp);
		break;
	default:
		break;
	}
	return 0;
}

/*
 * LDP-SYNC holddown timer routines
 */
static void ospf_ldp_sync_holddown_timer(struct event *thread)
{
	struct interface *ifp;
	struct ospf_if_params *params;
	struct ldp_sync_info *ldp_sync_info;

	/* holddown timer expired:
	 *  didn't receive msg from LDP indicating sync-complete
	 *  restore interface cost to original value
	 */
	ifp = EVENT_ARG(thread);
	params = IF_DEF_PARAMS(ifp);
	if (params->ldp_sync_info) {
		ldp_sync_info = params->ldp_sync_info;

		ldp_sync_info->state = LDP_IGP_SYNC_STATE_REQUIRED_UP;

		ols_debug("%s: holddown timer expired for %s state: %s",
			  __func__, ifp->name, "Sync achieved");

		ospf_if_recalculate_output_cost(ifp);
	}
}

void ospf_ldp_sync_holddown_timer_add(struct interface *ifp)
{
	struct ospf_if_params *params;
	struct ldp_sync_info *ldp_sync_info;

	params = IF_DEF_PARAMS(ifp);
	ldp_sync_info = params->ldp_sync_info;

	/* Start holddown timer:
	 *  this timer is used to keep interface cost at LSInfinity
	 *  once expires returns cost to original value
	 *  if timer is already running or holddown time is off just return
	 */
	if (ldp_sync_info->t_holddown ||
	    ldp_sync_info->holddown == LDP_IGP_SYNC_HOLDDOWN_DEFAULT)
		return;

	ols_debug("%s: start holddown timer for %s time %d", __func__,
		  ifp->name, ldp_sync_info->holddown);

	event_add_timer(master, ospf_ldp_sync_holddown_timer, ifp,
			ldp_sync_info->holddown, &ldp_sync_info->t_holddown);
}

/*
 * LDP-SYNC exit routes.
 */
void ospf_ldp_sync_gbl_exit(struct ospf *ospf, bool remove)
{
	struct interface *ifp;
	struct vrf *vrf;

	/* ospf is being removed
	 *  stop any holddown timers
	 */
	if (CHECK_FLAG(ospf->ldp_sync_cmd.flags, LDP_SYNC_FLAG_ENABLE)) {
		/* unregister with opaque client to recv LDP-IGP Sync msgs */
		zclient_unregister_opaque(zclient,
					  LDP_IGP_SYNC_IF_STATE_UPDATE);
		zclient_unregister_opaque(zclient,
					  LDP_IGP_SYNC_ANNOUNCE_UPDATE);

		/* disable LDP globally */
		UNSET_FLAG(ospf->ldp_sync_cmd.flags, LDP_SYNC_FLAG_ENABLE);
		UNSET_FLAG(ospf->ldp_sync_cmd.flags, LDP_SYNC_FLAG_HOLDDOWN);
		ospf->ldp_sync_cmd.holddown = LDP_IGP_SYNC_HOLDDOWN_DEFAULT;

		/* turn off LDP-IGP Sync on all OSPF interfaces */
		vrf = vrf_lookup_by_id(ospf->vrf_id);
		FOR_ALL_INTERFACES (vrf, ifp)
			ospf_ldp_sync_if_remove(ifp, remove);
	}
}

/*
 * LDP-SYNC routes used by set commands.
 */
void ospf_if_set_ldp_sync_enable(struct ospf *ospf, struct interface *ifp)
{
	struct ospf_if_params *params;
	struct ldp_sync_info *ldp_sync_info;

	/* called when setting LDP-SYNC at the global level:
	 *  specified on interface overrides global config
	 *  if ptop link send msg to LDP indicating ldp-sync enabled
	 */
	if (if_is_loopback(ifp))
		return;

	params = IF_DEF_PARAMS(ifp);
	if (params->ldp_sync_info == NULL)
		params->ldp_sync_info = ldp_sync_info_create();
	ldp_sync_info = params->ldp_sync_info;

	/* config on interface, overrides global config. */
	if (CHECK_FLAG(ldp_sync_info->flags, LDP_SYNC_FLAG_IF_CONFIG))
		if (ldp_sync_info->enabled != LDP_IGP_SYNC_ENABLED)
			return;

	ldp_sync_info->enabled = LDP_IGP_SYNC_ENABLED;

	ols_debug("%s: enable if %s", __func__, ifp->name);

	/* send message to LDP if ptop link */
	if (params->type == OSPF_IFTYPE_POINTOPOINT ||
	    if_is_pointopoint(ifp)) {
		ldp_sync_info->state = LDP_IGP_SYNC_STATE_REQUIRED_NOT_UP;
		ospf_ldp_sync_state_req_msg(ifp);
	} else {
		ldp_sync_info->state = LDP_IGP_SYNC_STATE_NOT_REQUIRED;
		zlog_debug("%s: Sync only runs on P2P links %s", __func__,
			   ifp->name);
	}
}

void ospf_if_set_ldp_sync_holddown(struct ospf *ospf, struct interface *ifp)
{
	struct ospf_if_params *params;
	struct ldp_sync_info *ldp_sync_info;

	/* called when setting LDP-SYNC at the global level:
	 *  specified on interface overrides global config.
	 */
	if (if_is_loopback(ifp))
		return;

	params = IF_DEF_PARAMS(ifp);
	if (params->ldp_sync_info == NULL)
		params->ldp_sync_info = ldp_sync_info_create();
	ldp_sync_info = params->ldp_sync_info;

	/* config on interface, overrides global config. */
	if (CHECK_FLAG(ldp_sync_info->flags, LDP_SYNC_FLAG_HOLDDOWN))
		return;
	if (CHECK_FLAG(ospf->ldp_sync_cmd.flags, LDP_SYNC_FLAG_HOLDDOWN))
		ldp_sync_info->holddown = ospf->ldp_sync_cmd.holddown;
	else
		ldp_sync_info->holddown = LDP_IGP_SYNC_HOLDDOWN_DEFAULT;
}

/*
 * LDP-SYNC routines used by show commands.
 */

void ospf_ldp_sync_show_info(struct vty *vty, struct ospf *ospf,
			     json_object *json_vrf, bool use_json)
{

	if (CHECK_FLAG(ospf->ldp_sync_cmd.flags, LDP_SYNC_FLAG_ENABLE)) {
		if (use_json) {
			json_object_boolean_true_add(json_vrf,
						     "mplsLdpIgpSyncEnabled");
			json_object_int_add(json_vrf, "mplsLdpIgpSyncHolddown",
					    ospf->ldp_sync_cmd.holddown);
		} else {
			vty_out(vty, " MPLS LDP-IGP Sync is enabled\n");
			if (ospf->ldp_sync_cmd.holddown == 0)
				vty_out(vty,
					" MPLS LDP-IGP Sync holddown timer is disabled\n");
			else
				vty_out(vty,
					" MPLS LDP-IGP Sync holddown timer %d sec\n",
					ospf->ldp_sync_cmd.holddown);
		}
	}
}

static void show_ip_ospf_mpls_ldp_interface_sub(struct vty *vty,
					       struct ospf_interface *oi,
					       struct interface *ifp,
					       json_object *json_interface_sub,
					       bool use_json)
{
	const char *ldp_state;
	struct ospf_if_params *params;
	char timebuf[OSPF_TIME_DUMP_SIZE];
	struct ldp_sync_info *ldp_sync_info;

	params = IF_DEF_PARAMS(oi->ifp);
	if (params->ldp_sync_info == NULL)
		return;

	ldp_sync_info = params->ldp_sync_info;
	if (use_json) {
		if (ldp_sync_info->enabled == LDP_IGP_SYNC_ENABLED)
			json_object_boolean_true_add(json_interface_sub,
						     "ldpIgpSyncEnabled");
		else
			json_object_boolean_false_add(json_interface_sub,
						     "ldpIgpSyncEnabled");

		json_object_int_add(json_interface_sub, "holdDownTimeInSec",
				    ldp_sync_info->holddown);

	} else {
		vty_out(vty, "%-10s\n", ifp->name);
		vty_out(vty, "  LDP-IGP Synchronization enabled: %s\n",
			ldp_sync_info->enabled == LDP_IGP_SYNC_ENABLED
			? "yes"
			: "no");
		vty_out(vty, "  Holddown timer in seconds: %u\n",
			ldp_sync_info->holddown);
	}

	switch (ldp_sync_info->state) {
	case LDP_IGP_SYNC_STATE_REQUIRED_UP:
		if (use_json)
			json_object_string_add(json_interface_sub,
					       "ldpIgpSyncState",
					       "Sync achieved");
		else
			vty_out(vty, "  State: Sync achieved\n");
		break;
	case LDP_IGP_SYNC_STATE_REQUIRED_NOT_UP:
		if (ldp_sync_info->t_holddown != NULL) {
			if (use_json) {
				long time_store;

				time_store = monotime_until(
					&ldp_sync_info->t_holddown->u.sands,
					NULL)
					/1000LL;

				json_object_int_add(json_interface_sub,
						    "ldpIgpSyncTimeRemainInMsec",
						    time_store);

				json_object_string_add(json_interface_sub,
						       "ldpIgpSyncState",
						       "Holding down until Sync");
			} else {
				vty_out(vty,
					"  Holddown timer is running %s remaining\n",
					ospf_timer_dump(
						ldp_sync_info->t_holddown,
						timebuf,
						sizeof(timebuf)));

				vty_out(vty,
					"  State: Holding down until Sync\n");
			}
		} else {
			if (use_json)
				json_object_string_add(json_interface_sub,
						       "ldpIgpSyncState",
						       "Sync not achieved");
			else
				vty_out(vty, "  State: Sync not achieved\n");
		}
		break;
	case LDP_IGP_SYNC_STATE_NOT_REQUIRED:
	default:
		if (IF_DEF_PARAMS(ifp)->type != OSPF_IFTYPE_POINTOPOINT &&
		    !if_is_pointopoint(ifp))
			ldp_state = "Sync not required: non-p2p link";
		else
			ldp_state = "Sync not required";

		if (use_json)
			json_object_string_add(json_interface_sub,
					       "ldpIgpSyncState",
					       ldp_state);
		else
			vty_out(vty, "  State: %s\n", ldp_state);
		break;
	}
}

static int show_ip_ospf_mpls_ldp_interface_common(struct vty *vty,
						  struct ospf *ospf,
						  char *intf_name,
						  json_object *json,
						  bool use_json)
{
	struct interface *ifp;
	struct vrf *vrf = vrf_lookup_by_id(ospf->vrf_id);
	json_object *json_interface_sub = NULL;

	if (intf_name == NULL) {
		/* Show All Interfaces.*/
		FOR_ALL_INTERFACES (vrf, ifp) {
			struct route_node *rn;
			struct ospf_interface *oi;

			if (ospf_oi_count(ifp) == 0 && !use_json) {
				if (!if_is_up(ifp))
					vty_out(vty, "%s\n  Interface down\n",
						ifp->name);
				continue;
			}
			for (rn = route_top(IF_OIFS(ifp)); rn;
			     rn = route_next(rn)) {
				oi = rn->info;

				if (oi == NULL)
					continue;

				if (use_json) {
					json_interface_sub =
						json_object_new_object();
				}
				show_ip_ospf_mpls_ldp_interface_sub(
					vty, oi, ifp, json_interface_sub,
					use_json);

				if (use_json) {
					json_object_object_add(
						json, ifp->name,
						json_interface_sub);
				}
			}
		}
	} else {
		/* Interface name is specified. */
		ifp = if_lookup_by_name(intf_name, ospf->vrf_id);
		if (ifp != NULL) {
			struct route_node *rn;
			struct ospf_interface *oi;

			if (ospf_oi_count(ifp) == 0 && !use_json) {
				if (if_is_up(ifp))
					vty_out(vty, "%s\n  OSPF not enabled\n",
						ifp->name);
				else
					vty_out(vty, "%s\n  Interface down\n",
						ifp->name);
				return CMD_SUCCESS;
			}
			for (rn = route_top(IF_OIFS(ifp)); rn;
			     rn = route_next(rn)) {
				oi = rn->info;

				if (oi == NULL)
					continue;

				if (use_json)
					json_interface_sub =
						json_object_new_object();

				show_ip_ospf_mpls_ldp_interface_sub(
					vty, oi, ifp, json_interface_sub,
					use_json);

				if (use_json) {
					json_object_object_add(
						json,	ifp->name,
						json_interface_sub);
				}
			}
		}
	}
	return CMD_SUCCESS;
}

/*
 * Write the global LDP-SYNC configuration.
 */
void ospf_ldp_sync_write_config(struct vty *vty, struct ospf *ospf)
{
	if (CHECK_FLAG(ospf->ldp_sync_cmd.flags, LDP_SYNC_FLAG_ENABLE))
		vty_out(vty, " mpls ldp-sync\n");
	if (CHECK_FLAG(ospf->ldp_sync_cmd.flags, LDP_SYNC_FLAG_HOLDDOWN))
		vty_out(vty, " mpls ldp-sync holddown %u\n",
			ospf->ldp_sync_cmd.holddown);
}

/*
 * Write the interface LDP-SYNC configuration.
 */
void ospf_ldp_sync_if_write_config(struct vty *vty,
				   struct ospf_if_params *params)

{
	struct ldp_sync_info *ldp_sync_info;

	ldp_sync_info = params->ldp_sync_info;
	if (ldp_sync_info == NULL)
		return;

	if (CHECK_FLAG(ldp_sync_info->flags, LDP_SYNC_FLAG_IF_CONFIG)) {
		if (ldp_sync_info->enabled == LDP_IGP_SYNC_ENABLED)
			vty_out(vty, " ip ospf mpls ldp-sync\n");
		else
			vty_out(vty, " no ip ospf mpls ldp-sync\n");
	}
	if (CHECK_FLAG(ldp_sync_info->flags, LDP_SYNC_FLAG_HOLDDOWN))
		vty_out(vty, " ip ospf mpls ldp-sync holddown %u\n",
			ldp_sync_info->holddown);
}

/*
 * LDP-SYNC commands.
 */
#include "ospfd/ospf_ldp_sync_clippy.c"

DEFPY (ospf_mpls_ldp_sync,
       ospf_mpls_ldp_sync_cmd,
       "mpls ldp-sync",
       "MPLS specific commands\n"
       "Enable MPLS LDP-IGP Sync\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	struct vrf *vrf = vrf_lookup_by_id(ospf->vrf_id);
	struct interface *ifp;

	if (ospf->vrf_id != VRF_DEFAULT) {
		vty_out(vty, "ldp-sync only runs on DEFAULT VRF\n");
		return CMD_ERR_NOTHING_TODO;
	}

	/* register with opaque client to recv LDP-IGP Sync msgs */
	zclient_register_opaque(zclient, LDP_IGP_SYNC_IF_STATE_UPDATE);
	zclient_register_opaque(zclient, LDP_IGP_SYNC_ANNOUNCE_UPDATE);

	if (!CHECK_FLAG(ospf->ldp_sync_cmd.flags, LDP_SYNC_FLAG_ENABLE)) {
		SET_FLAG(ospf->ldp_sync_cmd.flags, LDP_SYNC_FLAG_ENABLE);
		/* turn on LDP-IGP Sync on all ptop OSPF interfaces */
		FOR_ALL_INTERFACES (vrf, ifp)
			ospf_if_set_ldp_sync_enable(ospf, ifp);
	}
	return CMD_SUCCESS;
}

DEFPY (no_ospf_mpls_ldp_sync,
       no_ospf_mpls_ldp_sync_cmd,
       "no mpls ldp-sync",
       NO_STR
       "MPLS specific commands\n"
       "Disable MPLS LDP-IGP Sync\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	ospf_ldp_sync_gbl_exit(ospf, true);
	return CMD_SUCCESS;
}

DEFPY (ospf_mpls_ldp_sync_holddown,
       ospf_mpls_ldp_sync_holddown_cmd,
       "mpls ldp-sync holddown (1-10000)",
       "MPLS specific commands\n"
       "Enable MPLS LDP-IGP Sync\n"
       "Set holddown timer\n"
       "seconds\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	struct vrf *vrf = vrf_lookup_by_id(ospf->vrf_id);
	struct interface *ifp;

	if (ospf->vrf_id != VRF_DEFAULT) {
		vty_out(vty, "ldp-sync only runs on DEFAULT VRF\n");
		return CMD_ERR_NOTHING_TODO;
	}

	SET_FLAG(ospf->ldp_sync_cmd.flags, LDP_SYNC_FLAG_HOLDDOWN);
	ospf->ldp_sync_cmd.holddown = holddown;
	/* set holddown time on all OSPF interfaces */
	FOR_ALL_INTERFACES (vrf, ifp)
		ospf_if_set_ldp_sync_holddown(ospf, ifp);

	return CMD_SUCCESS;
}

DEFPY (no_ospf_mpls_ldp_sync_holddown,
       no_ospf_mpls_ldp_sync_holddown_cmd,
       "no mpls ldp-sync holddown [<(1-10000)>]",
       NO_STR
       "MPLS specific commands\n"
       "Disable MPLS LDP-IGP Sync\n"
       "holddown timer disable\n"
       "Time in seconds\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	struct vrf *vrf = vrf_lookup_by_id(ospf->vrf_id);
	struct interface *ifp;

	if (CHECK_FLAG(ospf->ldp_sync_cmd.flags, LDP_SYNC_FLAG_HOLDDOWN)) {
		UNSET_FLAG(ospf->ldp_sync_cmd.flags, LDP_SYNC_FLAG_HOLDDOWN);
		ospf->ldp_sync_cmd.holddown = LDP_IGP_SYNC_HOLDDOWN_DEFAULT;
		/* turn off holddown timer on all OSPF interfaces */
		FOR_ALL_INTERFACES (vrf, ifp)
			ospf_if_set_ldp_sync_holddown(ospf, ifp);
	}
	return CMD_SUCCESS;
}


DEFPY (mpls_ldp_sync,
       mpls_ldp_sync_cmd,
       "ip ospf mpls ldp-sync",
       IP_STR
       "OSPF interface commands\n"
       MPLS_STR
       MPLS_LDP_SYNC_STR)
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct ospf_if_params *params;
	struct ldp_sync_info *ldp_sync_info;

	if (if_is_loopback(ifp)) {
		vty_out(vty, "ldp-sync does not run on loopback interface\n");
		return CMD_ERR_NOTHING_TODO;
	}

	if (ifp->vrf->vrf_id != VRF_DEFAULT) {
		vty_out(vty, "ldp-sync only runs on DEFAULT VRF\n");
		return CMD_ERR_NOTHING_TODO;
	}

	params = IF_DEF_PARAMS(ifp);
	if (params->ldp_sync_info == NULL)
		params->ldp_sync_info = ldp_sync_info_create();

	ldp_sync_info = params->ldp_sync_info;

	SET_FLAG(ldp_sync_info->flags, LDP_SYNC_FLAG_IF_CONFIG);
	ldp_sync_info->enabled = LDP_IGP_SYNC_ENABLED;
	if (params->type == OSPF_IFTYPE_POINTOPOINT || if_is_pointopoint(ifp)) {
		ldp_sync_info->state = LDP_IGP_SYNC_STATE_REQUIRED_NOT_UP;
		ospf_ldp_sync_state_req_msg(ifp);
	} else {
		zlog_debug("ldp_sync: only runs on P2P links %s", ifp->name);
		ldp_sync_info->state = LDP_IGP_SYNC_STATE_NOT_REQUIRED;
	}
	return CMD_SUCCESS;
}

DEFPY (no_mpls_ldp_sync,
       no_mpls_ldp_sync_cmd,
       "no ip ospf mpls ldp-sync",
       NO_STR
       IP_STR
       "OSPF interface commands\n"
       MPLS_STR
       NO_MPLS_LDP_SYNC_STR)
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct ospf_if_params *params;
	struct ldp_sync_info *ldp_sync_info;

	if (if_is_loopback(ifp)) {
		vty_out(vty, "ldp-sync: does not run on loopback interface\n");
		return CMD_ERR_NOTHING_TODO;
	}

	if (ifp->vrf->vrf_id != VRF_DEFAULT) {
		vty_out(vty, "ldp-sync only runs on DEFAULT VRF\n");
		return CMD_ERR_NOTHING_TODO;
	}

	params = IF_DEF_PARAMS(ifp);
	if (params->ldp_sync_info == NULL)
		params->ldp_sync_info = ldp_sync_info_create();

	ldp_sync_info = params->ldp_sync_info;

	/* disable LDP-SYNC on an interface
	 *  stop holddown timer if running
	 *  restore ospf cost
	 */
	UNSET_FLAG(ldp_sync_info->flags, LDP_SYNC_FLAG_IF_CONFIG);
	ldp_sync_info->enabled = LDP_IGP_SYNC_DEFAULT;
	ldp_sync_info->state = LDP_IGP_SYNC_STATE_NOT_REQUIRED;
	EVENT_OFF(ldp_sync_info->t_holddown);
	ospf_if_recalculate_output_cost(ifp);

	return CMD_SUCCESS;
}

DEFPY (mpls_ldp_sync_holddown,
       mpls_ldp_sync_holddown_cmd,
       "ip ospf mpls ldp-sync holddown (0-10000)",
       IP_STR
       "OSPF interface commands\n"
       MPLS_STR
       MPLS_LDP_SYNC_STR
       "Time to wait for LDP-SYNC to occur before restoring interface cost\n"
       "Time in seconds\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct ospf_if_params *params;
	struct ldp_sync_info *ldp_sync_info;

	if (if_is_loopback(ifp)) {
		vty_out(vty, "ldp-sync: does not run on loopback interface\n");
		return CMD_ERR_NOTHING_TODO;
	}

	if (ifp->vrf->vrf_id != VRF_DEFAULT) {
		vty_out(vty, "ldp-sync only runs on DEFAULT VRF\n");
		return CMD_ERR_NOTHING_TODO;
	}

	params = IF_DEF_PARAMS(ifp);
	if (params->ldp_sync_info == NULL)
		params->ldp_sync_info = ldp_sync_info_create();

	ldp_sync_info = params->ldp_sync_info;

	SET_FLAG(ldp_sync_info->flags, LDP_SYNC_FLAG_HOLDDOWN);
	ldp_sync_info->holddown = holddown;

	return CMD_SUCCESS;
}

DEFPY (no_mpls_ldp_sync_holddown,
       no_mpls_ldp_sync_holddown_cmd,
       "no ip ospf mpls ldp-sync holddown [<(1-10000)>]",
       NO_STR
       IP_STR
       "OSPF interface commands\n"
       MPLS_STR
       NO_MPLS_LDP_SYNC_STR
       NO_MPLS_LDP_SYNC_HOLDDOWN_STR
       "Time in seconds\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct ospf_if_params *params;
	struct ldp_sync_info *ldp_sync_info;
	struct ospf *ospf;

	if (if_is_loopback(ifp)) {
		vty_out(vty, "ldp-sync: does not run on loopback interface\n");
		return CMD_ERR_NOTHING_TODO;
	}

	if (ifp->vrf->vrf_id != VRF_DEFAULT) {
		vty_out(vty, "ldp-sync only runs on DEFAULT VRF\n");
		return CMD_ERR_NOTHING_TODO;
	}

	params = IF_DEF_PARAMS(ifp);
	ldp_sync_info = params->ldp_sync_info;
	if (ldp_sync_info == NULL)
		return CMD_SUCCESS;

	/* use global configured value if set */
	if (CHECK_FLAG(ldp_sync_info->flags, LDP_SYNC_FLAG_HOLDDOWN)) {
		UNSET_FLAG(ldp_sync_info->flags, LDP_SYNC_FLAG_HOLDDOWN);
		ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
		if (ospf && CHECK_FLAG(ospf->ldp_sync_cmd.flags,
			       LDP_SYNC_FLAG_HOLDDOWN))
			ldp_sync_info->holddown = ospf->ldp_sync_cmd.holddown;
		else
			ldp_sync_info->holddown = LDP_IGP_SYNC_HOLDDOWN_DEFAULT;
	}
	return CMD_SUCCESS;
}

DEFPY (show_ip_ospf_mpls_ldp_interface,
       show_ip_ospf_mpls_ldp_interface_cmd,
       "show ip ospf mpls ldp-sync [interface <INTERFACE|all>] [json]",
       SHOW_STR
       IP_STR
       "OSPF information\n"
       MPLS_STR
       "LDP-IGP Sync information\n"
       "Interface information\n"
       "Interface name\n"
       "All interfaces\n"
       JSON_STR)
{
	struct ospf *ospf;
	bool uj = use_json(argc, argv);
	char *intf_name = NULL;
	int ret = CMD_SUCCESS;
	int idx_intf = 0;
	json_object *json = NULL;

	if (argv_find(argv, argc, "INTERFACE", &idx_intf))
		intf_name = argv[idx_intf]->arg;

	if (uj)
		json = json_object_new_object();

	/* Display default ospf (instance 0) info */
	ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
	if (ospf == NULL || !ospf->oi_running) {
		if (uj)
			vty_json(vty, json);
		else
			vty_out(vty, "%% OSPF instance not found\n");
		return CMD_SUCCESS;
	}

	if (!CHECK_FLAG(ospf->ldp_sync_cmd.flags, LDP_SYNC_FLAG_ENABLE)) {
		if (uj)
			vty_json(vty, json);
		else
			vty_out(vty, "LDP-sync is disabled\n");
		return CMD_SUCCESS;
	}

	ret = show_ip_ospf_mpls_ldp_interface_common(vty, ospf, intf_name,
						     json, uj);
	if (uj)
		vty_json(vty, json);

	return ret;
}

void ospf_ldp_sync_init(void)
{
	/* Install global ldp-igp sync commands */
	install_element(OSPF_NODE, &ospf_mpls_ldp_sync_cmd);
	install_element(OSPF_NODE, &no_ospf_mpls_ldp_sync_cmd);
	install_element(OSPF_NODE, &ospf_mpls_ldp_sync_holddown_cmd);
	install_element(OSPF_NODE, &no_ospf_mpls_ldp_sync_holddown_cmd);

	/* Interface lsp-igp sync commands */
	install_element(INTERFACE_NODE, &mpls_ldp_sync_cmd);
	install_element(INTERFACE_NODE, &no_mpls_ldp_sync_cmd);
	install_element(INTERFACE_NODE, &mpls_ldp_sync_holddown_cmd);
	install_element(INTERFACE_NODE, &no_mpls_ldp_sync_holddown_cmd);

	/* "show ip ospf mpls ldp interface" commands. */
	install_element(VIEW_NODE, &show_ip_ospf_mpls_ldp_interface_cmd);

	hook_register(ospf_ism_change, ospf_ldp_sync_ism_change);

}
