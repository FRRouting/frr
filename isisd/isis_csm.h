/*
 * IS-IS Rout(e)ing protocol - isis_csm.h
 *                             IS-IS circuit state machine
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 *
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
#ifndef _ZEBRA_ISIS_CSM_H
#define _ZEBRA_ISIS_CSM_H

/*
 * Circuit states
 */
enum isis_circuit_state {
	C_STATE_NA,
	C_STATE_INIT, /* Connected to interface */
	C_STATE_CONF, /* Configured for ISIS    */
	C_STATE_UP,   /* CONN | CONF            */
};

/*
 * Circuit events
 */
enum isis_circuit_event {
	ISIS_ENABLE = 1,
	IF_UP_FROM_Z,
	ISIS_DISABLE,
	IF_DOWN_FROM_Z,
};

struct isis_circuit *isis_csm_state_change(enum isis_circuit_event event,
					   struct isis_circuit *circuit,
					   void *arg);

#endif /* _ZEBRA_ISIS_CSM_H */
