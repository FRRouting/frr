/*
 * IS-IS Rout(e)ing protocol - isis_events.h
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public Licenseas published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>

#include "log.h"
#include "memory.h"
#include "if.h"
#include "linklist.h"
#include "command.h"
#include "thread.h"
#include "hash.h"
#include "prefix.h"
#include "stream.h"
#include "table.h"

#include "isisd/dict.h"
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

/* debug isis-spf spf-events
 4w4d: ISIS-Spf (tlt): L2 SPF needed, new adjacency, from 0x609229F4
 4w4d: ISIS-Spf (tlt): L2, 0000.0000.0042.01-00 TLV contents changed, code 0x2
 4w4d: ISIS-Spf (tlt): L2, new LSP 0 DEAD.BEEF.0043.00-00
 4w5d: ISIS-Spf (tlt): L1 SPF needed, periodic SPF, from 0x6091C844
 4w5d: ISIS-Spf (tlt): L2 SPF needed, periodic SPF, from 0x6091C844
*/

void isis_event_circuit_state_change(struct isis_circuit *circuit,
				     struct isis_area *area, int up)
{
	area->circuit_state_changes++;

	if (isis->debugs & DEBUG_EVENTS)
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
	if (level == 1) {
		if (!circuit->is_passive)
			thread_add_timer(master, send_l1_psnp, circuit,
					 isis_jitter(circuit->psnp_interval[0],
						     PSNP_JITTER),
					 &circuit->t_send_psnp[0]);

		if (circuit->circ_type == CIRCUIT_T_BROADCAST) {
			thread_add_timer(master, isis_run_dr_l1, circuit,
					 2 * circuit->hello_interval[0],
					 &circuit->u.bc.t_run_dr[0]);

			thread_add_timer(master, send_lan_l1_hello, circuit,
					 isis_jitter(circuit->hello_interval[0],
						     IIH_JITTER),
					 &circuit->u.bc.t_send_lan_hello[0]);

			circuit->u.bc.lan_neighs[0] = list_new();
		}
	} else {
		if (!circuit->is_passive)
			thread_add_timer(master, send_l2_psnp, circuit,
					 isis_jitter(circuit->psnp_interval[1],
						     PSNP_JITTER),
					 &circuit->t_send_psnp[1]);

		if (circuit->circ_type == CIRCUIT_T_BROADCAST) {
			thread_add_timer(master, isis_run_dr_l2, circuit,
					 2 * circuit->hello_interval[1],
					 &circuit->u.bc.t_run_dr[1]);

			thread_add_timer(master, send_lan_l2_hello, circuit,
					 isis_jitter(circuit->hello_interval[1],
						     IIH_JITTER),
					 &circuit->u.bc.t_send_lan_hello[1]);

			circuit->u.bc.lan_neighs[1] = list_new();
		}
	}

	return;
}

static void circuit_resign_level(struct isis_circuit *circuit, int level)
{
	int idx = level - 1;

	THREAD_TIMER_OFF(circuit->t_send_csnp[idx]);
	THREAD_TIMER_OFF(circuit->t_send_psnp[idx]);

	if (circuit->circ_type == CIRCUIT_T_BROADCAST) {
		THREAD_TIMER_OFF(circuit->u.bc.t_send_lan_hello[idx]);
		THREAD_TIMER_OFF(circuit->u.bc.t_run_dr[idx]);
		THREAD_TIMER_OFF(circuit->u.bc.t_refresh_pseudo_lsp[idx]);
		circuit->lsp_regenerate_pending[idx] = 0;
		circuit->u.bc.run_dr_elect[idx] = 0;
		if (circuit->u.bc.lan_neighs[idx] != NULL)
			list_delete_and_null(&circuit->u.bc.lan_neighs[idx]);
	}

	return;
}

void isis_circuit_is_type_set(struct isis_circuit *circuit, int newtype)
{
	if (circuit->state != C_STATE_UP) {
		circuit->is_type = newtype;
		return;
	}

	if (isis->debugs & DEBUG_EVENTS)
		zlog_debug("ISIS-Evt (%s) circuit type change %s -> %s",
			   circuit->area->area_tag,
			   circuit_t2string(circuit->is_type),
			   circuit_t2string(newtype));

	if (circuit->is_type == newtype)
		return; /* No change */

	if (!(newtype & circuit->area->is_type)) {
		zlog_err(
			"ISIS-Evt (%s) circuit type change - invalid level %s because"
			" area is %s",
			circuit->area->area_tag, circuit_t2string(newtype),
			circuit_t2string(circuit->area->is_type));
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

void isis_event_adjacency_state_change(struct isis_adjacency *adj, int newstate)
{
	/* adjacency state change event.
	 * - the only proto-type was supported */

	/* invalid arguments */
	if (!adj || !adj->circuit || !adj->circuit->area)
		return;

	if (isis->debugs & DEBUG_EVENTS)
		zlog_debug("ISIS-Evt (%s) Adjacency State change",
			   adj->circuit->area->area_tag);

	/* LSP generation again */
	lsp_regenerate_schedule(adj->circuit->area, IS_LEVEL_1 | IS_LEVEL_2, 0);

	return;
}

/* events supporting code */

int isis_event_dis_status_change(struct thread *thread)
{
	struct isis_circuit *circuit;

	circuit = THREAD_ARG(thread);

	/* invalid arguments */
	if (!circuit || !circuit->area)
		return 0;
	if (isis->debugs & DEBUG_EVENTS)
		zlog_debug("ISIS-Evt (%s) DIS status change",
			   circuit->area->area_tag);

	/* LSP generation again */
	lsp_regenerate_schedule(circuit->area, IS_LEVEL_1 | IS_LEVEL_2, 0);

	return 0;
}

void isis_event_auth_failure(char *area_tag, const char *error_string,
			     uint8_t *sysid)
{
	if (isis->debugs & DEBUG_EVENTS)
		zlog_debug("ISIS-Evt (%s) Authentication failure %s from %s",
			   area_tag, error_string, sysid_print(sysid));

	return;
}
