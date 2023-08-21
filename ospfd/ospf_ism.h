// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPF version 2  Interface State Machine.
 *   From RFC2328 [OSPF Version 2]
 * Copyright (C) 1999 Toshiaki Takada
 */

#ifndef _ZEBRA_OSPF_ISM_H
#define _ZEBRA_OSPF_ISM_H

#include "hook.h"

/* OSPF Interface State Machine Status. */
#define ISM_DependUpon                    0
#define ISM_Down                          1
#define ISM_Loopback                      2
#define ISM_Waiting                       3
#define ISM_PointToPoint                  4
#define ISM_DROther                       5
#define ISM_Backup                        6
#define ISM_DR                            7
#define OSPF_ISM_STATE_MAX   	          8

/* OSPF Interface State Machine Event. */
#define ISM_NoEvent                       0
#define ISM_InterfaceUp                   1
#define ISM_WaitTimer                     2
#define ISM_BackupSeen                    3
#define ISM_NeighborChange                4
#define ISM_LoopInd                       5
#define ISM_UnloopInd                     6
#define ISM_InterfaceDown                 7
#define OSPF_ISM_EVENT_MAX                8

#define OSPF_ISM_WRITE_ON(O)                                                   \
	do {                                                                   \
		if (oi->on_write_q == 0) {                                     \
			listnode_add((O)->oi_write_q, oi);                     \
			oi->on_write_q = 1;                                    \
		}                                                              \
		if (!list_isempty((O)->oi_write_q))                            \
			event_add_write(master, ospf_write, (O), (O)->fd,      \
					&(O)->t_write);                        \
	} while (0)

/* Macro for OSPF ISM timer turn on. */
#define OSPF_ISM_TIMER_ON(T, F, V) event_add_timer(master, (F), oi, (V), &(T))

#define OSPF_ISM_TIMER_MSEC_ON(T, F, V)                                        \
	event_add_timer_msec(master, (F), oi, (V), &(T))

/* convenience macro to set hello timer correctly, according to
 * whether fast-hello is set or not
 */
#define OSPF_HELLO_TIMER_ON(O)                                                 \
	do {                                                                   \
		if (OSPF_IF_PARAM((O), fast_hello))                            \
			OSPF_ISM_TIMER_MSEC_ON(                                \
				(O)->t_hello, ospf_hello_timer,                \
				1000 / OSPF_IF_PARAM((O), fast_hello));        \
		else                                                           \
			OSPF_ISM_TIMER_ON((O)->t_hello, ospf_hello_timer,      \
					  OSPF_IF_PARAM((O), v_hello));        \
	} while (0)

/* Macro for OSPF schedule event. */
#define OSPF_ISM_EVENT_SCHEDULE(I, E)                                          \
	event_add_event(master, ospf_ism_event, (I), (E), NULL)

/* Macro for OSPF execute event. */
#define OSPF_ISM_EVENT_EXECUTE(I, E)                                           \
	event_execute(master, ospf_ism_event, (I), (E), NULL)

/* Prototypes. */
extern void ospf_ism_event(struct event *thread);
extern void ism_change_status(struct ospf_interface *, int);
extern void ospf_hello_timer(struct event *thread);
extern int ospf_dr_election(struct ospf_interface *oi);

DECLARE_HOOK(ospf_ism_change,
	     (struct ospf_interface * oi, int state, int oldstate),
	     (oi, state, oldstate));

#endif /* _ZEBRA_OSPF_ISM_H */
