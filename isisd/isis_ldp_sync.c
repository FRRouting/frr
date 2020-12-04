/**
 * isis_ldp_sync.c: ISIS LDP-IGP Sync  handling routines
 * Copyright (C) 2020 Volta Networks, Inc.
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

#include <zebra.h>
#include <string.h>

#include "monotime.h"
#include "memory.h"
#include "thread.h"
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

#include "isisd/isis_constants.h"
#include "isisd/isis_common.h"
#include "isisd/isis_flags.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_lsp.h"
#include "isisd/isis_pdu.h"
#include "isisd/isis_network.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_constants.h"
#include "isisd/isis_adjacency.h"
#include "isisd/isis_dr.h"
#include "isisd/isisd.h"
#include "isisd/isis_csm.h"
#include "isisd/isis_events.h"
#include "isisd/isis_te.h"
#include "isisd/isis_mt.h"
#include "isisd/isis_errors.h"
#include "isisd/isis_tx_queue.h"
#include "isisd/isis_nb.h"
#include "isisd/isis_ldp_sync.h"

extern struct zclient *zclient;

/*
 * LDP-SYNC msg between IGP and LDP
 */
int isis_ldp_sync_state_update(struct ldp_igp_sync_if_state state)
{
	struct interface *ifp;
	struct isis_circuit *circuit = NULL;
	struct isis_area *area;
	struct listnode *node;
	struct isis *isis = isis_lookup_by_vrfid(VRF_DEFAULT);

	/* if isis is not enabled or LDP-SYNC is not configured ignore */
	if (!isis ||
	    !CHECK_FLAG(isis->ldp_sync_cmd.flags, LDP_SYNC_FLAG_ENABLE))
		return 0;

	/* lookup circuit */
	ifp = if_lookup_by_index(state.ifindex, VRF_DEFAULT);
	if (ifp == NULL)
		return 0;

	for (ALL_LIST_ELEMENTS_RO(isis->area_list, node, area)) {
		circuit = circuit_lookup_by_ifp(ifp, area->circuit_list);
		if (circuit != NULL)
			break;
	}

	/* if isis is not enabled or LDP-SYNC is not configured ignore */
	if (circuit == NULL ||
	    !CHECK_FLAG(isis->ldp_sync_cmd.flags, LDP_SYNC_FLAG_ENABLE))
		return 0;

	/* received ldp-sync interface state from LDP */
	ils_debug("ldp_sync: rcvd %s from LDP if %s",
		  state.sync_start ? "sync-start" : "sync-complete", ifp->name);
	if (state.sync_start)
		isis_ldp_sync_if_start(circuit, false);
	else
		isis_ldp_sync_if_complete(circuit);

	return 0;
}

int isis_ldp_sync_announce_update(struct ldp_igp_sync_announce announce)
{
	struct isis_area *area;
	struct listnode *node;
	struct vrf *vrf;
	struct interface *ifp;
	struct isis_circuit *circuit;
	struct isis *isis = isis_lookup_by_vrfid(VRF_DEFAULT);

	/* if isis is not enabled or LDP-SYNC is not configured ignore */
	if (!isis ||
	    !CHECK_FLAG(isis->ldp_sync_cmd.flags, LDP_SYNC_FLAG_ENABLE))
		return 0;

	if (announce.proto != ZEBRA_ROUTE_LDP)
		return 0;

	ils_debug("ldp_sync: rcvd announce from LDP");

	/* LDP just started up:
	 *  set cost to LSInfinity
	 *  send request to LDP for LDP-SYNC state for each interface
	 */
	vrf = vrf_lookup_by_id(VRF_DEFAULT);
	FOR_ALL_INTERFACES (vrf, ifp) {
		for (ALL_LIST_ELEMENTS_RO(isis->area_list, node, area)) {
			circuit = circuit_lookup_by_ifp(ifp,
				area->circuit_list);
			if (circuit == NULL)
				continue;
			isis_ldp_sync_if_start(circuit, true);
		}
	}

	return 0;
}

void isis_ldp_sync_state_req_msg(struct isis_circuit *circuit)
{
	struct ldp_igp_sync_if_state_req request;
	struct interface *ifp = circuit->interface;

	ils_debug("ldp_sync: send state request to LDP for %s",
		  ifp->name);

	strlcpy(request.name, ifp->name, sizeof(ifp->name));
	request.proto = LDP_IGP_SYNC_IF_STATE_REQUEST;
	request.ifindex = ifp->ifindex;

	zclient_send_opaque(zclient, LDP_IGP_SYNC_IF_STATE_REQUEST,
		(uint8_t *)&request, sizeof(request));
}

/*
 * LDP-SYNC general interface routines
 */
void isis_ldp_sync_if_init(struct isis_circuit *circuit, struct isis *isis)
{
	struct ldp_sync_info *ldp_sync_info;
	struct interface *ifp = circuit->interface;

	/* called when ISIS is configured on an interface
	 *  if LDP-IGP Sync is configured globally set state
	 *  and if ptop interface LDP LDP-SYNC is enabled
	 */
	ils_debug("ldp_sync: init if %s ", ifp->name);
	if (circuit->ldp_sync_info == NULL)
		circuit->ldp_sync_info = ldp_sync_info_create();
	ldp_sync_info = circuit->ldp_sync_info;

	/* specifed on interface overrides global config. */
	if (!CHECK_FLAG(ldp_sync_info->flags, LDP_SYNC_FLAG_HOLDDOWN))
		ldp_sync_info->holddown = isis->ldp_sync_cmd.holddown;

	if (!CHECK_FLAG(ldp_sync_info->flags, LDP_SYNC_FLAG_IF_CONFIG))
		ldp_sync_info->enabled = LDP_IGP_SYNC_ENABLED;

	if ((circuit->circ_type == CIRCUIT_T_P2P || if_is_pointopoint(ifp)) &&
	    ldp_sync_info->enabled == LDP_IGP_SYNC_ENABLED)
		ldp_sync_info->state = LDP_IGP_SYNC_STATE_REQUIRED_NOT_UP;
}

void isis_ldp_sync_if_start(struct isis_circuit *circuit,
	bool send_state_req)
{
	struct ldp_sync_info *ldp_sync_info;

	ldp_sync_info = circuit->ldp_sync_info;

	/* Start LDP-SYNC on this interface:
	 *  set cost of interface to LSInfinity so traffic will use different
	 *  interface until LDP has learned all labels from peer
	 *  start holddown timer if configured
	 *  send msg to LDP to get LDP-SYNC state
	 */
	if (ldp_sync_info &&
	    ldp_sync_info->enabled == LDP_IGP_SYNC_ENABLED &&
	    ldp_sync_info->state != LDP_IGP_SYNC_STATE_NOT_REQUIRED) {
		ils_debug("ldp_sync: start on if %s state: %s",
			  circuit->interface->name, "Holding down until Sync");
		ldp_sync_info->state = LDP_IGP_SYNC_STATE_REQUIRED_NOT_UP;
		isis_ldp_sync_set_if_metric(circuit, true);
		isis_ldp_sync_holddown_timer_add(circuit);

		if (send_state_req)
			isis_ldp_sync_state_req_msg(circuit);
	}
}

void isis_ldp_sync_if_complete(struct isis_circuit *circuit)
{
	struct ldp_sync_info *ldp_sync_info;

	ldp_sync_info = circuit->ldp_sync_info;

	/* received sync-complete from LDP:
	 *  set state to up
	 *  stop timer
	 *  restore interface cost to original value
	 */
	if (ldp_sync_info && ldp_sync_info->enabled == LDP_IGP_SYNC_ENABLED) {
		if (ldp_sync_info->state == LDP_IGP_SYNC_STATE_REQUIRED_NOT_UP)
			ldp_sync_info->state = LDP_IGP_SYNC_STATE_REQUIRED_UP;

		THREAD_OFF(ldp_sync_info->t_holddown);

		isis_ldp_sync_set_if_metric(circuit, true);
	}
}

void isis_ldp_sync_ldp_fail(struct isis_circuit *circuit)
{
	struct ldp_sync_info *ldp_sync_info;

	ldp_sync_info = circuit->ldp_sync_info;

	/* LDP client close detected:
	 *  stop holddown timer
	 *  set cost of interface to LSInfinity so traffic will use different
	 *  interface until LDP restarts and has learned all labels from peer
	 */
	if (ldp_sync_info &&
	    ldp_sync_info->enabled == LDP_IGP_SYNC_ENABLED &&
	    ldp_sync_info->state != LDP_IGP_SYNC_STATE_NOT_REQUIRED) {
		THREAD_OFF(ldp_sync_info->t_holddown);
		ldp_sync_info->state = LDP_IGP_SYNC_STATE_REQUIRED_NOT_UP;
		isis_ldp_sync_set_if_metric(circuit, true);
	}
}

void isis_ldp_sync_if_remove(struct isis_circuit *circuit, bool remove)
{
	struct ldp_sync_info *ldp_sync_info;

	if (circuit->ldp_sync_info == NULL)
		return;

	ldp_sync_info = circuit->ldp_sync_info;

	/* Stop LDP-SYNC on this interface:
	 *  if holddown timer is running stop it
	 *  delete ldp instance on interface
	 *  restore metric
	 */
	ils_debug("ldp_sync: remove if %s", circuit->interface
		  ? circuit->interface->name : "");

	THREAD_OFF(ldp_sync_info->t_holddown);
	ldp_sync_info->state = LDP_IGP_SYNC_STATE_NOT_REQUIRED;
	isis_ldp_sync_set_if_metric(circuit, true);
	if (remove) {
		/* ISIS instance being removed free ldp-sync info */
		ldp_sync_info_free((struct ldp_sync_info **)&(ldp_sync_info));
		circuit->ldp_sync_info = NULL;
	}
}

static int isis_ldp_sync_adj_state_change(struct isis_adjacency *adj)
{
	struct isis_circuit *circuit = adj->circuit;
	struct ldp_sync_info *ldp_sync_info;
	struct isis *isis = isis_lookup_by_vrfid(VRF_DEFAULT);

	if (!isis ||
	    !CHECK_FLAG(isis->ldp_sync_cmd.flags, LDP_SYNC_FLAG_ENABLE) ||
	    circuit->interface->vrf_id != VRF_DEFAULT ||
	    if_is_loopback(circuit->interface))
		return 0;

	if (circuit->ldp_sync_info == NULL)
		isis_ldp_sync_if_init(circuit, isis);
	ldp_sync_info = circuit->ldp_sync_info;

	if (ldp_sync_info->enabled != LDP_IGP_SYNC_ENABLED)
		return 0;

	if (adj->adj_state == ISIS_ADJ_UP) {
		if (circuit->circ_type == CIRCUIT_T_P2P ||
		    if_is_pointopoint(circuit->interface)) {
			/* If LDP-SYNC is configure on interface then start */
			ldp_sync_info->state =
				LDP_IGP_SYNC_STATE_REQUIRED_NOT_UP;
			isis_ldp_sync_if_start(circuit, true);
		} else {
			/* non ptop link so don't run ldp-sync */
			ldp_sync_info->state = LDP_IGP_SYNC_STATE_NOT_REQUIRED;
			isis_ldp_sync_set_if_metric(circuit, true);
		}
	} else {
		/* If LDP-SYNC is configure on this interface then stop it */
		if (circuit->circ_type == CIRCUIT_T_P2P ||
		    if_is_pointopoint(circuit->interface))
			ldp_sync_info->state =
				LDP_IGP_SYNC_STATE_REQUIRED_NOT_UP;
		else
			ldp_sync_info->state = LDP_IGP_SYNC_STATE_NOT_REQUIRED;

		ils_debug("ldp_sync: down on if %s", circuit->interface->name);
		ldp_sync_if_down(circuit->ldp_sync_info);
	}

	return 0;
}

bool isis_ldp_sync_if_metric_config(struct isis_circuit *circuit, int level,
				    int metric)
{
	struct ldp_sync_info *ldp_sync_info = circuit->ldp_sync_info;
	struct isis *isis = isis_lookup_by_vrfid(VRF_DEFAULT);

	/* configured interface metric has been changed:
	 *   if LDP-IGP Sync is running and metric has been set to LSInfinity
	 *   change saved value so when ldp-sync completes proper metric is
	 *   restored
	 */
	if (isis &&
	    CHECK_FLAG(isis->ldp_sync_cmd.flags, LDP_SYNC_FLAG_ENABLE) &&
	    ldp_sync_info != NULL) {

		if (CHECK_FLAG(ldp_sync_info->flags,
			       LDP_SYNC_FLAG_SET_METRIC)) {
			ldp_sync_info->metric[level-1] = metric;
			ldp_sync_info->metric[level-1] = metric;
			return false;
		}
	}
	return true;
}

void isis_ldp_sync_set_if_metric(struct isis_circuit *circuit, bool run_regen)
{
	struct ldp_sync_info *ldp_sync_info;

	/* set interface metric:
	 *   if LDP-IGP Sync is starting set metric so interface
	 *   is used only as last resort
	 *   else restore metric to original value
	 */
	if (circuit->ldp_sync_info == NULL || circuit->area == NULL)
		return;

	ldp_sync_info = circuit->ldp_sync_info;
	if (ldp_sync_if_is_enabled(ldp_sync_info)) {
		/* if metric already set to LSInfinity just return */
		if (CHECK_FLAG(ldp_sync_info->flags, LDP_SYNC_FLAG_SET_METRIC))
			return;

		SET_FLAG(ldp_sync_info->flags, LDP_SYNC_FLAG_SET_METRIC);
		if (circuit->is_type & IS_LEVEL_1) {
			if (circuit->area->newmetric) {
				ldp_sync_info->metric[0] =
					circuit->te_metric[0];
				circuit->te_metric[0] =
					ISIS_WIDE_METRIC_INFINITY;
			} else {
				ldp_sync_info->metric[0] = circuit->metric[0];
				circuit->metric[0] =
					ISIS_NARROW_METRIC_INFINITY;
			}
		}
		if (circuit->is_type & IS_LEVEL_2) {
			if (circuit->area->newmetric) {
				ldp_sync_info->metric[1] =
					circuit->te_metric[1];
				circuit->te_metric[1] =
					ISIS_WIDE_METRIC_INFINITY;
			} else {
				ldp_sync_info->metric[1] = circuit->metric[1];
				circuit->metric[1] =
					ISIS_NARROW_METRIC_INFINITY;
			}
		}
	} else {
		/* if metric already restored just return */
		if (!CHECK_FLAG(ldp_sync_info->flags, LDP_SYNC_FLAG_SET_METRIC))
			return;

		UNSET_FLAG(ldp_sync_info->flags, LDP_SYNC_FLAG_SET_METRIC);
		if (circuit->is_type & IS_LEVEL_1) {
			circuit->te_metric[0] = ldp_sync_info->metric[0];
			circuit->metric[0] = ldp_sync_info->metric[0];
		}
		if (circuit->is_type & IS_LEVEL_2) {
			circuit->te_metric[1] = ldp_sync_info->metric[1];
			circuit->metric[1] = ldp_sync_info->metric[1];
		}
	}

	if (run_regen)
		lsp_regenerate_schedule(circuit->area, circuit->is_type, 0);
}


/*
 * LDP-SYNC holddown timer routines
 */
static int isis_ldp_sync_holddown_timer(struct thread *thread)
{
	struct isis_circuit *circuit;
	struct ldp_sync_info *ldp_sync_info;

	/* holddown timer expired:
	 *  didn't receive msg from LDP indicating sync-complete
	 *  restore interface cost to original value
	 */
	circuit = THREAD_ARG(thread);
	if (circuit->ldp_sync_info == NULL)
		return 0;

	ldp_sync_info = circuit->ldp_sync_info;

	ldp_sync_info->state = LDP_IGP_SYNC_STATE_REQUIRED_UP;
	ldp_sync_info->t_holddown = NULL;

	ils_debug("ldp_sync: holddown timer expired for %s state:sync achieved",
		  circuit->interface->name);

	isis_ldp_sync_set_if_metric(circuit, true);
	return 0;
}

void isis_ldp_sync_holddown_timer_add(struct isis_circuit *circuit)
{
	struct ldp_sync_info *ldp_sync_info;

	ldp_sync_info = circuit->ldp_sync_info;

	/* Start holddown timer:
	 *  this timer is used to keep interface cost at LSInfinity
	 *  once expires returns cost to original value
	 *  if timer is already running or holddown time is off just return
	 */
	if (ldp_sync_info->t_holddown ||
	    ldp_sync_info->holddown == LDP_IGP_SYNC_HOLDDOWN_DEFAULT)
		return;

	ils_debug("ldp_sync: start holddown timer for %s time %d",
		  circuit->interface->name, ldp_sync_info->holddown);

	thread_add_timer(master, isis_ldp_sync_holddown_timer,
			 circuit, ldp_sync_info->holddown,
			 &ldp_sync_info->t_holddown);
}

/*
 * LDP-SYNC handle client close routine
 */
void isis_ldp_sync_handle_client_close(
	struct zapi_client_close_info *info)
{
	struct isis_area *area;
	struct listnode *node;
	struct isis_circuit *circuit;
	struct interface *ifp;
	struct vrf *vrf = vrf_lookup_by_id(VRF_DEFAULT);
	struct isis *isis = isis_lookup_by_vrfid(VRF_DEFAULT);

	/* if isis is not enabled or LDP-SYNC is not configured ignore */
	if (!isis ||
	    !CHECK_FLAG(isis->ldp_sync_cmd.flags, LDP_SYNC_FLAG_ENABLE))
		return;

	/* Check if the LDP main client session closed */
	if (info->proto != ZEBRA_ROUTE_LDP || info->session_id == 0)
		return;

	/* Handle the zebra notification that the LDP client session closed.
	 *  set cost to LSInfinity
	 *  send request to LDP for LDP-SYNC state for each interface
	 */
	zlog_err("ldp_sync: LDP down");

	FOR_ALL_INTERFACES (vrf, ifp) {
		for (ALL_LIST_ELEMENTS_RO(isis->area_list, node, area)) {
			circuit = circuit_lookup_by_ifp(ifp,
							area->circuit_list);
			if (circuit == NULL)
				continue;
			isis_ldp_sync_if_start(circuit, true);
		}
	}

	return;
}

/*
 * LDP-SYNC routes used by set commands.
 */

void isis_if_set_ldp_sync_enable(struct isis_circuit *circuit)
{
	struct ldp_sync_info *ldp_sync_info;
	struct isis *isis = isis_lookup_by_vrfid(VRF_DEFAULT);

	/* called when setting LDP-SYNC at the global level:
	 *  specifed on interface overrides global config
	 *  if ptop link send msg to LDP indicating ldp-sync enabled
 	 */
	if (!isis || if_is_loopback(circuit->interface))
		return;

	if (CHECK_FLAG(isis->ldp_sync_cmd.flags, LDP_SYNC_FLAG_ENABLE)) {
		if (circuit->ldp_sync_info == NULL)
			isis_ldp_sync_if_init(circuit, isis);
		ldp_sync_info = circuit->ldp_sync_info;

		/* config on interface, overrides global config. */
		if (CHECK_FLAG(ldp_sync_info->flags, LDP_SYNC_FLAG_IF_CONFIG))
			if (ldp_sync_info->enabled != LDP_IGP_SYNC_ENABLED)
			    return;

		ldp_sync_info->enabled = LDP_IGP_SYNC_ENABLED;
		ils_debug("ldp_sync: enable if %s", circuit->interface->name);

		/* send message to LDP if ptop link */
		if (circuit->circ_type == CIRCUIT_T_P2P ||
		    if_is_pointopoint(circuit->interface)) {
			ldp_sync_info->state =
				LDP_IGP_SYNC_STATE_REQUIRED_NOT_UP;
			isis_ldp_sync_state_req_msg(circuit);
		} else {
			ldp_sync_info->state = LDP_IGP_SYNC_STATE_NOT_REQUIRED;
			zlog_debug("ldp_sync: Sync only runs on P2P links %s",
				   circuit->interface->name);
		}
	} else
		/* delete LDP sync even if configured on an interface */
		isis_ldp_sync_if_remove(circuit, false);
}

void isis_if_set_ldp_sync_holddown(struct isis_circuit *circuit)
{
	struct ldp_sync_info *ldp_sync_info;
	struct isis *isis = isis_lookup_by_vrfid(VRF_DEFAULT);

	/* called when setting LDP-SYNC at the global level:
	 *  specifed on interface overrides global config.
	 */
	if (!isis || if_is_loopback(circuit->interface))
		return;

	if (circuit->ldp_sync_info == NULL)
		isis_ldp_sync_if_init(circuit, isis);
	ldp_sync_info = circuit->ldp_sync_info;

	/* config on interface, overrides global config. */
	if (CHECK_FLAG(ldp_sync_info->flags, LDP_SYNC_FLAG_HOLDDOWN))
		return;
	if (CHECK_FLAG(isis->ldp_sync_cmd.flags, LDP_SYNC_FLAG_HOLDDOWN))
		ldp_sync_info->holddown = isis->ldp_sync_cmd.holddown;
	else
		ldp_sync_info->holddown = LDP_IGP_SYNC_HOLDDOWN_DEFAULT;
}

void isis_ldp_sync_gbl_exit(bool remove)
{
	struct isis_area *area;
	struct listnode *node;
	struct isis_circuit *circuit;
	struct interface *ifp;
	struct vrf *vrf = vrf_lookup_by_id(VRF_DEFAULT);
	struct isis *isis = isis_lookup_by_vrfid(VRF_DEFAULT);

	/* if you delete LDP-SYNC at a gobal level is clears all LDP-SYNC
	 * configuration, even interface configuration
	 */
	if (isis &&
	    CHECK_FLAG(isis->ldp_sync_cmd.flags, LDP_SYNC_FLAG_ENABLE)) {
		/* register with opaque client to recv LDP-IGP Sync msgs */
		zclient_unregister_opaque(zclient,
					  LDP_IGP_SYNC_IF_STATE_UPDATE);
		zclient_unregister_opaque(zclient,
					  LDP_IGP_SYNC_ANNOUNCE_UPDATE);

		/* disable LDP-SYNC globally */
		UNSET_FLAG(isis->ldp_sync_cmd.flags, LDP_SYNC_FLAG_ENABLE);
		UNSET_FLAG(isis->ldp_sync_cmd.flags, LDP_SYNC_FLAG_HOLDDOWN);
		isis->ldp_sync_cmd.holddown = LDP_IGP_SYNC_HOLDDOWN_DEFAULT;

		/* remove LDP-SYNC on all ISIS interfaces */
		FOR_ALL_INTERFACES (vrf, ifp) {
			for (ALL_LIST_ELEMENTS_RO(isis->area_list, node,
						  area)) {
				circuit = circuit_lookup_by_ifp(ifp,
					area->circuit_list);
				if (circuit == NULL)
					continue;
				isis_ldp_sync_if_remove(circuit, remove);
			}
		}
	}
}

/*
 * LDP-SYNC routines used by show commands.
 */

static void isis_circuit_ldp_sync_print_vty(struct isis_circuit *circuit,
	struct vty *vty)
{
	struct ldp_sync_info *ldp_sync_info;
	const char *ldp_state;

	if (circuit->ldp_sync_info == NULL ||
	    if_is_loopback(circuit->interface))
		return;

	ldp_sync_info = circuit->ldp_sync_info;
	vty_out(vty, "%-16s\n", circuit->interface->name);
	if (circuit->state == C_STATE_CONF) {
		vty_out(vty, "  Interface down\n");
		return;
	}

	vty_out(vty, "  LDP-IGP Synchronization enabled: %s\n",
		ldp_sync_info->enabled == LDP_IGP_SYNC_ENABLED
		? "yes"
		: "no");
	vty_out(vty, "  holddown timer in seconds: %u\n",
		ldp_sync_info->holddown);

	switch (ldp_sync_info->state) {
	case LDP_IGP_SYNC_STATE_REQUIRED_UP:
		vty_out(vty, "  State: Sync achieved\n");
		break;
	case LDP_IGP_SYNC_STATE_REQUIRED_NOT_UP:
		if (ldp_sync_info->t_holddown != NULL) {
			struct timeval remain = thread_timer_remain(
				ldp_sync_info->t_holddown);
			vty_out(vty,
				"  Holddown timer is running %lld.%03lld remaining\n",
				(long long)remain.tv_sec,
				(long long)remain.tv_usec/1000);

			vty_out(vty, "  State: Holding down until Sync\n");
		} else
			vty_out(vty, "  State: Sync not achieved\n");
		break;
	case LDP_IGP_SYNC_STATE_NOT_REQUIRED:
	default:
		if ((circuit->circ_type != CIRCUIT_T_P2P &&
		     !if_is_pointopoint(circuit->interface)) &&
		    circuit->circ_type != CIRCUIT_T_UNKNOWN)
			ldp_state = "Sync not required: non-p2p link";
		else
			ldp_state = "Sync not required";
		vty_out(vty, "  State: %s\n", ldp_state);
		break;
	}
}

DEFUN (show_isis_mpls_ldp_interface,
       show_isis_mpls_ldp_interface_cmd,
       "show " PROTO_NAME " mpls ldp-sync [interface <INTERFACE|all>]",
       SHOW_STR
       PROTO_HELP
       MPLS_STR
       "LDP-IGP Sync information\n"
       "Interface information\n"
       "Interface name\n"
       "All interfaces\n")
{
	char *ifname = NULL;
	int idx_intf = 0;
	struct listnode *anode, *cnode;
	struct isis_area *area;
	struct isis_circuit *circuit;
	struct isis *isis = isis_lookup_by_vrfid(VRF_DEFAULT);
	bool found = false;

	if (!isis) {
		vty_out(vty, "IS-IS Routing Process not enabled\n");
		return CMD_SUCCESS;
	}

	if (!CHECK_FLAG(isis->ldp_sync_cmd.flags, LDP_SYNC_FLAG_ENABLE)) {
		vty_out(vty, "LDP-sync is disabled\n");
		return CMD_SUCCESS;
	}

	if (argv_find(argv, argc, "INTERFACE", &idx_intf))
		ifname = argv[idx_intf]->arg;

	for (ALL_LIST_ELEMENTS_RO(isis->area_list, anode, area)) {
		for (ALL_LIST_ELEMENTS_RO(area->circuit_list, cnode, circuit))
			if (!ifname)
				isis_circuit_ldp_sync_print_vty(circuit, vty);
			else if (strcmp(circuit->interface->name, ifname)
				 == 0) {
				isis_circuit_ldp_sync_print_vty(circuit, vty);
				found = true;
			}
	}

	if (found == false && ifname)
		vty_out(vty, "%-16s\n  ISIS not enabled\n", ifname);

	return CMD_SUCCESS;
}

void isis_ldp_sync_init(void)
{

	/* "show ip isis mpls ldp interface" commands. */
	install_element(VIEW_NODE, &show_isis_mpls_ldp_interface_cmd);

	/* register for adjacency state changes */
	hook_register(isis_adj_state_change_hook,
		      isis_ldp_sync_adj_state_change);
}
