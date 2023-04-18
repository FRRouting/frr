// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IS-IS Rout(e)ing protocol - isis_csm.h
 *                             IS-IS circuit state machine
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 *
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
