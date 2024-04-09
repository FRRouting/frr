// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * EIGRP Macros Definition.
 * Copyright (C) 2013-2014
 * Authors:
 *   Donnie Savage
 *   Jan Janovic
 *   Matej Perina
 *   Peter Orsag
 *   Peter Paluch
 */

#ifndef _ZEBRA_EIGRP_MACROS_H_
#define _ZEBRA_EIGRP_MACROS_H_

//--------------------------------------------------------------------------

#define EIGRP_IF_STRING_MAXLEN  40
#define IF_NAME(I)      eigrp_if_name_string ((I))

//--------------------------------------------------------------------------

#define EIGRP_PACKET_MTU(mtu) ((mtu) - (sizeof(struct ip)))

/* Topology Macros */


/* FSM macros*/
#define EIGRP_FSM_EVENT_SCHEDULE(I, E)                                         \
	event_add_event(master, eigrp_fsm_event, (I), (E))

#endif /* _ZEBRA_EIGRP_MACROS_H_ */
