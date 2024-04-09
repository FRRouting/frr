// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * isis_ldp_sync.c: ISIS LDP-IGP Sync  handling routines
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

	/* lookup circuit */
	ifp = if_lookup_by_index(state.ifindex, VRF_DEFAULT);
	if (ifp == NULL)
		return 0;

	circuit = ifp->info;
	if (circuit == NULL)
		return 0;

	/* if isis is not enabled or LDP-SYNC is not configured ignore */
	area = circuit->area;
	if (area == NULL
	    || !CHECK_FLAG(area->ldp_sync_cmd.flags, LDP_SYNC_FLAG_ENABLE))
		return 0;

	/* received ldp-sync interface state from LDP */
	ils_debug("%s: rcvd %s from LDP if %s", __func__,
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
	struct listnode *anode, *cnode;
	struct isis_circuit *circuit;
	struct isis *isis = isis_lookup_by_vrfid(VRF_DEFAULT);

	/* if isis is not enabled ignore */
	if (!isis)
		return 0;

	if (announce.proto != ZEBRA_ROUTE_LDP)
		return 0;

	ils_debug("%s: rcvd announce from LDP", __func__);

	/* LDP just started up:
	 *  set cost to LSInfinity
	 *  send request to LDP for LDP-SYNC state for each interface
	 */
	for (ALL_LIST_ELEMENTS_RO(isis->area_list, anode, area)) {
		if (!CHECK_FLAG(area->ldp_sync_cmd.flags, LDP_SYNC_FLAG_ENABLE))
			continue;

		for (ALL_LIST_ELEMENTS_RO(area->circuit_list, cnode, circuit))
			isis_ldp_sync_if_start(circuit, true);
	}

	return 0;
}

void isis_ldp_sync_state_req_msg(struct isis_circuit *circuit)
{
	struct ldp_igp_sync_if_state_req request;
	struct interface *ifp = circuit->interface;

	ils_debug("%s: send state request to LDP for %s", __func__, ifp->name);

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
		ils_debug("%s: start on if %s state: %s", __func__,
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

		EVENT_OFF(ldp_sync_info->t_holddown);

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
		EVENT_OFF(ldp_sync_info->t_holddown);
		ldp_sync_info->state = LDP_IGP_SYNC_STATE_REQUIRED_NOT_UP;
		isis_ldp_sync_set_if_metric(circuit, true);
	}
}

static int isis_ldp_sync_adj_state_change(struct isis_adjacency *adj)
{
	struct isis_circuit *circuit = adj->circuit;
	struct ldp_sync_info *ldp_sync_info = circuit->ldp_sync_info;
	struct isis_area *area = circuit->area;

	if (!CHECK_FLAG(area->ldp_sync_cmd.flags, LDP_SYNC_FLAG_ENABLE)
	    || circuit->interface->vrf->vrf_id != VRF_DEFAULT
	    || if_is_loopback(circuit->interface))
		return 0;

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

		ils_debug("%s: down on if %s", __func__,
			  circuit->interface->name);
		ldp_sync_if_down(circuit->ldp_sync_info);
	}

	return 0;
}

bool isis_ldp_sync_if_metric_config(struct isis_circuit *circuit, int level,
				    int metric)
{
	struct ldp_sync_info *ldp_sync_info = circuit->ldp_sync_info;
	struct isis_area *area = circuit->area;

	/* configured interface metric has been changed:
	 *   if LDP-IGP Sync is running and metric has been set to LSInfinity
	 *   change saved value so when ldp-sync completes proper metric is
	 *   restored
	 */
	if (area && CHECK_FLAG(area->ldp_sync_cmd.flags, LDP_SYNC_FLAG_ENABLE)
	    && ldp_sync_info != NULL) {

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
static void isis_ldp_sync_holddown_timer(struct event *thread)
{
	struct isis_circuit *circuit;
	struct ldp_sync_info *ldp_sync_info;

	/* holddown timer expired:
	 *  didn't receive msg from LDP indicating sync-complete
	 *  restore interface cost to original value
	 */
	circuit = EVENT_ARG(thread);
	if (circuit->ldp_sync_info == NULL)
		return;

	ldp_sync_info = circuit->ldp_sync_info;

	ldp_sync_info->state = LDP_IGP_SYNC_STATE_REQUIRED_UP;
	ldp_sync_info->t_holddown = NULL;

	ils_debug("%s: holddown timer expired for %s state:sync achieved",
		  __func__, circuit->interface->name);

	isis_ldp_sync_set_if_metric(circuit, true);
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

	ils_debug("%s: start holddown timer for %s time %d", __func__,
		  circuit->interface->name, ldp_sync_info->holddown);

	event_add_timer(master, isis_ldp_sync_holddown_timer, circuit,
			ldp_sync_info->holddown, &ldp_sync_info->t_holddown);
}

/*
 * LDP-SYNC handle client close routine
 */
void isis_ldp_sync_handle_client_close(struct zapi_client_close_info *info)
{
	struct isis_area *area;
	struct listnode *anode, *cnode;
	struct isis_circuit *circuit;
	struct isis *isis = isis_lookup_by_vrfid(VRF_DEFAULT);

	/* if isis is not enabled ignore */
	if (!isis)
		return;

	/* Check if the LDP main client session closed */
	if (info->proto != ZEBRA_ROUTE_LDP || info->session_id == 0)
		return;

	/* Handle the zebra notification that the LDP client session closed.
	 *  set cost to LSInfinity
	 *  send request to LDP for LDP-SYNC state for each interface
	 */
	zlog_err("%s: LDP down", __func__);

	for (ALL_LIST_ELEMENTS_RO(isis->area_list, anode, area)) {
		if (!CHECK_FLAG(area->ldp_sync_cmd.flags, LDP_SYNC_FLAG_ENABLE))
			continue;

		for (ALL_LIST_ELEMENTS_RO(area->circuit_list, cnode, circuit))
			isis_ldp_sync_ldp_fail(circuit);
	}
}

/*
 * LDP-SYNC routes used by set commands.
 */

void isis_area_ldp_sync_enable(struct isis_area *area)
{
	struct isis_circuit *circuit;
	struct listnode *node;

	if (!CHECK_FLAG(area->ldp_sync_cmd.flags, LDP_SYNC_FLAG_ENABLE)) {
		SET_FLAG(area->ldp_sync_cmd.flags, LDP_SYNC_FLAG_ENABLE);

		for (ALL_LIST_ELEMENTS_RO(area->circuit_list, node, circuit))
			isis_if_ldp_sync_enable(circuit);
	}
}

void isis_area_ldp_sync_disable(struct isis_area *area)
{
	struct isis_circuit *circuit;
	struct listnode *node;

	if (CHECK_FLAG(area->ldp_sync_cmd.flags, LDP_SYNC_FLAG_ENABLE)) {
		for (ALL_LIST_ELEMENTS_RO(area->circuit_list, node, circuit))
			isis_if_ldp_sync_disable(circuit);

		UNSET_FLAG(area->ldp_sync_cmd.flags, LDP_SYNC_FLAG_ENABLE);

		UNSET_FLAG(area->ldp_sync_cmd.flags, LDP_SYNC_FLAG_HOLDDOWN);
		area->ldp_sync_cmd.holddown = LDP_IGP_SYNC_HOLDDOWN_DEFAULT;
	}
}

void isis_area_ldp_sync_set_holddown(struct isis_area *area, uint16_t holddown)
{
	struct isis_circuit *circuit;
	struct listnode *node;

	if (holddown == LDP_IGP_SYNC_HOLDDOWN_DEFAULT)
		UNSET_FLAG(area->ldp_sync_cmd.flags, LDP_SYNC_FLAG_HOLDDOWN);
	else
		SET_FLAG(area->ldp_sync_cmd.flags, LDP_SYNC_FLAG_HOLDDOWN);

	area->ldp_sync_cmd.holddown = holddown;

	for (ALL_LIST_ELEMENTS_RO(area->circuit_list, node, circuit))
		isis_if_set_ldp_sync_holddown(circuit);
}

void isis_if_ldp_sync_enable(struct isis_circuit *circuit)
{
	struct ldp_sync_info *ldp_sync_info = circuit->ldp_sync_info;
	struct isis_area *area = circuit->area;

	/* called when setting LDP-SYNC at the global level:
	 *  specified on interface overrides global config
	 *  if ptop link send msg to LDP indicating ldp-sync enabled
	 */
	if (if_is_loopback(circuit->interface))
		return;

	if (circuit->interface->vrf->vrf_id != VRF_DEFAULT)
		return;

	ils_debug("%s: enable if %s", __func__, circuit->interface->name);

	if (!CHECK_FLAG(area->ldp_sync_cmd.flags, LDP_SYNC_FLAG_ENABLE))
		return;

	/* config on interface, overrides global config. */
	if (CHECK_FLAG(ldp_sync_info->flags, LDP_SYNC_FLAG_IF_CONFIG))
		if (ldp_sync_info->enabled != LDP_IGP_SYNC_ENABLED)
			return;

	if (!CHECK_FLAG(ldp_sync_info->flags, LDP_SYNC_FLAG_HOLDDOWN))
		ldp_sync_info->holddown = area->ldp_sync_cmd.holddown;

	if (circuit->circ_type == CIRCUIT_T_P2P
	    || if_is_pointopoint(circuit->interface)) {
		ldp_sync_info->state = LDP_IGP_SYNC_STATE_REQUIRED_NOT_UP;
		isis_ldp_sync_state_req_msg(circuit);
	} else {
		ldp_sync_info->state = LDP_IGP_SYNC_STATE_NOT_REQUIRED;
		ils_debug("%s: Sync only runs on P2P links %s", __func__,
			  circuit->interface->name);
	}
}

void isis_if_ldp_sync_disable(struct isis_circuit *circuit)
{
	struct ldp_sync_info *ldp_sync_info = circuit->ldp_sync_info;
	struct isis_area *area = circuit->area;

	/* Stop LDP-SYNC on this interface:
	 *  if holddown timer is running stop it
	 *  delete ldp instance on interface
	 *  restore metric
	 */
	if (if_is_loopback(circuit->interface))
		return;

	ils_debug("%s: remove if %s", __func__, circuit->interface->name);

	if (!CHECK_FLAG(area->ldp_sync_cmd.flags, LDP_SYNC_FLAG_ENABLE))
		return;

	EVENT_OFF(ldp_sync_info->t_holddown);
	ldp_sync_info->state = LDP_IGP_SYNC_STATE_NOT_REQUIRED;
	isis_ldp_sync_set_if_metric(circuit, true);
}

void isis_if_set_ldp_sync_holddown(struct isis_circuit *circuit)
{
	struct ldp_sync_info *ldp_sync_info = circuit->ldp_sync_info;
	struct isis_area *area = circuit->area;

	/* called when setting LDP-SYNC at the global level:
	 *  specified on interface overrides global config.
	 */
	if (if_is_loopback(circuit->interface))
		return;

	/* config on interface, overrides global config. */
	if (CHECK_FLAG(ldp_sync_info->flags, LDP_SYNC_FLAG_HOLDDOWN))
		return;
	if (CHECK_FLAG(area->ldp_sync_cmd.flags, LDP_SYNC_FLAG_HOLDDOWN))
		ldp_sync_info->holddown = area->ldp_sync_cmd.holddown;
	else
		ldp_sync_info->holddown = LDP_IGP_SYNC_HOLDDOWN_DEFAULT;
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
			struct timeval remain =
				event_timer_remain(ldp_sync_info->t_holddown);
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
