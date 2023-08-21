// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPF version 2  Neighbor State Machine
 *   From RFC2328 [OSPF Version 2]
 *   Copyright (C) 1999 Toshiaki Takada
 */

#ifndef _ZEBRA_OSPF_NSM_H
#define _ZEBRA_OSPF_NSM_H

#include "hook.h"

/* OSPF Neighbor State Machine State. */
#define NSM_DependUpon          0
#define NSM_Deleted		1
#define NSM_Down		2
#define NSM_Attempt		3
#define NSM_Init		4
#define NSM_TwoWay		5
#define NSM_ExStart		6
#define NSM_Exchange		7
#define NSM_Loading		8
#define NSM_Full		9
#define OSPF_NSM_STATE_MAX     10

/* OSPF Neighbor State Machine Event. */
#define NSM_NoEvent	        0
#define NSM_HelloReceived	1 /* HelloReceived in the protocol */
#define NSM_Start		2
#define NSM_TwoWayReceived	3
#define NSM_NegotiationDone	4
#define NSM_ExchangeDone	5
#define NSM_BadLSReq		6
#define NSM_LoadingDone		7
#define NSM_AdjOK		8
#define NSM_SeqNumberMismatch	9
#define NSM_OneWayReceived     10
#define NSM_KillNbr	       11
#define NSM_InactivityTimer    12
#define NSM_LLDown	       13
#define OSPF_NSM_EVENT_MAX     14

/* Macro for OSPF NSM timer turn on. */
#define OSPF_NSM_TIMER_ON(T, F, V) event_add_timer(master, (F), nbr, (V), &(T))

/* Macro for OSPF NSM schedule event. */
#define OSPF_NSM_EVENT_SCHEDULE(N, E)                                          \
	event_add_event(master, ospf_nsm_event, (N), (E), NULL)

/* Macro for OSPF NSM execute event. */
#define OSPF_NSM_EVENT_EXECUTE(N, E)                                           \
	event_execute(master, ospf_nsm_event, (N), (E), NULL)

/* Prototypes. */
extern void ospf_nsm_event(struct event *e);
extern void ospf_check_nbr_loading(struct ospf_neighbor *nbr);
extern int ospf_db_summary_isempty(struct ospf_neighbor *nbr);
extern int ospf_db_summary_count(struct ospf_neighbor *nbr);
extern void ospf_db_summary_clear(struct ospf_neighbor *nbr);
extern int nsm_should_adj(struct ospf_neighbor *nbr);
DECLARE_HOOK(ospf_nsm_change,
	     (struct ospf_neighbor * on, int state, int oldstate),
	     (on, state, oldstate));

#endif /* _ZEBRA_OSPF_NSM_H */
