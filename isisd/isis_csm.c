/*
 * IS-IS Rout(e)ing protocol - isis_csm.c
 *                             IS-IS circuit state machine
 * Copyright (C) 2001,2002    Sampo Saaristo
 *                            Tampere University of Technology
 *                            Institute of Communications Engineering
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
#include "isisd/isis_errors.h"

static const char *const csm_statestr[] = {"C_STATE_NA", "C_STATE_INIT",
				     "C_STATE_CONF", "C_STATE_UP"};

#define STATE2STR(S) csm_statestr[S]

static const char *const csm_eventstr[] = {
	"NO_STATE",     "ISIS_ENABLE",    "IF_UP_FROM_Z",
	"ISIS_DISABLE", "IF_DOWN_FROM_Z",
};

#define EVENT2STR(E) csm_eventstr[E]

struct isis_circuit *isis_csm_state_change(enum isis_circuit_event event,
					   struct isis_circuit *circuit,
					   void *arg)
{
	enum isis_circuit_state old_state;
	struct isis_area *area = NULL;
	struct interface *ifp;

	assert(circuit);

	old_state = circuit->state;
	if (IS_DEBUG_EVENTS)
		zlog_debug("CSM_EVENT for %s: %s", circuit->interface->name,
			   EVENT2STR(event));

	switch (old_state) {
	case C_STATE_NA:
		switch (event) {
		case ISIS_ENABLE:
			area = arg;

			isis_circuit_configure(circuit, area);
			circuit->state = C_STATE_CONF;
			break;
		case IF_UP_FROM_Z:
			ifp = arg;

			isis_circuit_if_add(circuit, ifp);
			circuit->state = C_STATE_INIT;
			break;
		case ISIS_DISABLE:
			if (IS_DEBUG_EVENTS)
				zlog_debug("circuit %s already disabled",
					   circuit->interface->name);
			break;
		case IF_DOWN_FROM_Z:
			if (IS_DEBUG_EVENTS)
				zlog_debug("circuit %s already disconnected",
					   circuit->interface->name);
			break;
		}
		break;
	case C_STATE_INIT:
		switch (event) {
		case ISIS_ENABLE:
			area = arg;

			isis_circuit_configure(circuit, area);
			if (isis_circuit_up(circuit) != ISIS_OK) {
				isis_circuit_deconfigure(circuit, area);
				break;
			}
			circuit->state = C_STATE_UP;
			isis_event_circuit_state_change(circuit, circuit->area,
							1);
			break;
		case IF_UP_FROM_Z:
			if (IS_DEBUG_EVENTS)
				zlog_debug("circuit %s already connected",
					   circuit->interface->name);
			break;
		case ISIS_DISABLE:
			if (IS_DEBUG_EVENTS)
				zlog_debug("circuit %s already disabled",
					   circuit->interface->name);
			break;
		case IF_DOWN_FROM_Z:
			ifp = arg;

			isis_circuit_if_del(circuit, ifp);
			circuit->state = C_STATE_NA;
			break;
		}
		break;
	case C_STATE_CONF:
		switch (event) {
		case ISIS_ENABLE:
			if (IS_DEBUG_EVENTS)
				zlog_debug("circuit %s is already enabled",
					   circuit->interface->name);
			break;
		case IF_UP_FROM_Z:
			ifp = arg;

			isis_circuit_if_add(circuit, ifp);
			if (isis_circuit_up(circuit) != ISIS_OK) {
				isis_circuit_if_del(circuit, ifp);
				flog_err(
					EC_ISIS_CONFIG,
					"Could not bring up %s because of invalid config.",
					circuit->interface->name);
				break;
			}
			circuit->state = C_STATE_UP;
			isis_event_circuit_state_change(circuit, circuit->area,
							1);
			break;
		case ISIS_DISABLE:
			area = arg;

			isis_circuit_deconfigure(circuit, area);
			circuit->state = C_STATE_NA;
			break;
		case IF_DOWN_FROM_Z:
			if (IS_DEBUG_EVENTS)
				zlog_debug("circuit %s already disconnected",
					   circuit->interface->name);
			break;
		}
		break;
	case C_STATE_UP:
		switch (event) {
		case ISIS_ENABLE:
			if (IS_DEBUG_EVENTS)
				zlog_debug("circuit %s already enabled",
					   circuit->interface->name);
			break;
		case IF_UP_FROM_Z:
			if (IS_DEBUG_EVENTS)
				zlog_debug("circuit %s already connected",
					   circuit->interface->name);
			break;
		case ISIS_DISABLE:
			area = arg;

			isis_circuit_down(circuit);
			isis_circuit_deconfigure(circuit, area);
			circuit->state = C_STATE_INIT;
			isis_event_circuit_state_change(circuit, area, 0);
			break;
		case IF_DOWN_FROM_Z:
			ifp = arg;

			isis_circuit_down(circuit);
			isis_circuit_if_del(circuit, ifp);
			circuit->state = C_STATE_CONF;
			isis_event_circuit_state_change(circuit, circuit->area,
							0);
			break;
		}
		break;
	}

	if (IS_DEBUG_EVENTS)
		zlog_debug("CSM_STATE_CHANGE: %s -> %s ", STATE2STR(old_state),
			   STATE2STR(circuit->state));

	return circuit;
}
