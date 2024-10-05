// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IS-IS Rout(e)ing protocol - isis_events.h
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 */
#include <zebra.h>

#include "log.h"
#include "memory.h"
#include "if.h"
#include "linklist.h"
#include "command.h"
#include "frrevent.h"
#include "hash.h"
#include "prefix.h"
#include "stream.h"
#include "table.h"

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
#include "isisd/isis_spf.h"
#include "isisd/isis_errors.h"

void isis_event_circuit_state_change(struct isis_circuit *circuit,
				     struct isis_area *area, int up)
{
	area->circuit_state_changes++;

	if (IS_DEBUG_EVENTS)
		zlog_debug("ISIS-Evt (%s) circuit %s", area->area_tag,
			   up ? "up" : "down");

	/*
	 * Regenerate LSPs this affects
	 */
	lsp_regenerate_schedule(area, IS_LEVEL_1 | IS_LEVEL_2, 0);

	return;
}

static void circuit_commence_level(struct isis_circuit *circuit, int level)
{
	if (IS_DEBUG_EVENTS)
		zlog_debug(
			"ISIS-Evt (%s) circuit %u on iface %s commencing on L%d",
			circuit->area->area_tag, circuit->circuit_id,
			circuit->interface->name, level);

	if (!circuit->is_passive) {
		if (level == 1) {
			event_add_timer(master, send_l1_psnp, circuit,
					isis_jitter(circuit->psnp_interval[0],
						    PSNP_JITTER),
					&circuit->t_send_psnp[0]);
		} else {
			event_add_timer(master, send_l2_psnp, circuit,
					isis_jitter(circuit->psnp_interval[1],
						    PSNP_JITTER),
					&circuit->t_send_psnp[1]);
		}
	}

	if (circuit->circ_type == CIRCUIT_T_BROADCAST) {
		event_add_timer(master, isis_run_dr,
				&circuit->level_arg[level - 1],
				2 * circuit->hello_interval[level - 1],
				&circuit->u.bc.t_run_dr[level - 1]);

		send_hello_sched(circuit, level, TRIGGERED_IIH_DELAY);
		circuit->u.bc.lan_neighs[level - 1] = list_new();
		circuit->u.bc.adjdb[level - 1] = list_new();
	}
}

static void circuit_resign_level(struct isis_circuit *circuit, int level)
{
	int idx = level - 1;

	if (IS_DEBUG_EVENTS)
		zlog_debug(
			"ISIS-Evt (%s) circuit %u on iface %s resigning on L%d",
			circuit->area->area_tag, circuit->circuit_id,
			circuit->interface->name, level);

	EVENT_OFF(circuit->t_send_csnp[idx]);
	EVENT_OFF(circuit->t_send_psnp[idx]);

	if (circuit->circ_type == CIRCUIT_T_BROADCAST) {
		EVENT_OFF(circuit->u.bc.t_send_lan_hello[idx]);
		EVENT_OFF(circuit->u.bc.t_run_dr[idx]);
		EVENT_OFF(circuit->u.bc.t_refresh_pseudo_lsp[idx]);
		circuit->lsp_regenerate_pending[idx] = 0;
		circuit->u.bc.run_dr_elect[idx] = 0;
		circuit->u.bc.is_dr[idx] = 0;
		if (circuit->u.bc.lan_neighs[idx] != NULL)
			list_delete(&circuit->u.bc.lan_neighs[idx]);
		if (circuit->u.bc.adjdb[idx]) {
			circuit->u.bc.adjdb[idx]->del = isis_delete_adj;
			list_delete(&circuit->u.bc.adjdb[idx]);
		}
	}

	return;
}

void isis_circuit_is_type_set(struct isis_circuit *circuit, int newtype)
{
	if (!circuit->area) {
		circuit->is_type = newtype;
		return;
	}

	if (IS_DEBUG_EVENTS)
		zlog_debug("ISIS-Evt (%s) circuit type change %s -> %s",
			   circuit->area->area_tag,
			   circuit_t2string(circuit->is_type),
			   circuit_t2string(newtype));

	if (circuit->is_type == newtype)
		return; /* No change */

	if (!(newtype & circuit->area->is_type)) {
		flog_err(
			EC_ISIS_CONFIG,
			"ISIS-Evt (%s) circuit type change - invalid level %s because area is %s",
			circuit->area->area_tag, circuit_t2string(newtype),
			circuit_t2string(circuit->area->is_type));
		return;
	}

	if (circuit->state != C_STATE_UP) {
		circuit->is_type = newtype;
		return;
	}

	if (!circuit->is_passive) {
		switch (circuit->is_type) {
		case IS_LEVEL_1:
			if (newtype == IS_LEVEL_2)
				circuit_resign_level(circuit, 1);
			circuit_commence_level(circuit, 2);
			break;
		case IS_LEVEL_1_AND_2:
			if (newtype == IS_LEVEL_1)
				circuit_resign_level(circuit, 2);
			else
				circuit_resign_level(circuit, 1);
			break;
		case IS_LEVEL_2:
			if (newtype == IS_LEVEL_1)
				circuit_resign_level(circuit, 2);
			circuit_commence_level(circuit, 1);
			break;
		default:
			break;
		}
	}

	circuit->is_type = newtype;
	lsp_regenerate_schedule(circuit->area, IS_LEVEL_1 | IS_LEVEL_2, 0);

	return;
}

/* 04/18/2002 by Gwak. */
/**************************************************************************
 *
 * EVENTS for LSP generation
 *
 * 1) an Adajacency or Circuit Up/Down event
 * 2) a chnage in Circuit metric
 * 3) a change in Reachable Address metric
 * 4) a change in manualAreaAddresses
 * 5) a change in systemID
 * 6) a change in DIS status
 * 7) a chnage in the waiting status
 *
 * ***********************************************************************
 *
 * current support event
 *
 * 1) Adjacency Up/Down event
 * 6) a change in DIS status
 *
 * ***********************************************************************/

/* events supporting code */

void isis_event_dis_status_change(struct event *thread)
{
	struct isis_circuit *circuit;

	circuit = EVENT_ARG(thread);

	/* invalid arguments */
	if (!circuit || !circuit->area)
		return;
	if (IS_DEBUG_EVENTS)
		zlog_debug("ISIS-Evt (%s) DIS status change",
			   circuit->area->area_tag);

	/* LSP generation again */
	lsp_regenerate_schedule(circuit->area, IS_LEVEL_1 | IS_LEVEL_2, 0);
}

void isis_event_auth_failure(char *area_tag, const char *error_string,
			     uint8_t *sysid)
{
	if (IS_DEBUG_EVENTS)
		zlog_debug("ISIS-Evt (%s) Authentication failure %s from %pSY",
			   area_tag, error_string, sysid);

	return;
}
