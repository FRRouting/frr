// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPF version 2  Interface State Machine
 *   From RFC2328 [OSPF Version 2]
 * Copyright (C) 1999, 2000 Toshiaki Takada
 */

#include <zebra.h>

#include "frrevent.h"
#include "linklist.h"
#include "prefix.h"
#include "if.h"
#include "table.h"
#include "log.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_network.h"
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_packet.h"
#include "ospfd/ospf_flood.h"
#include "ospfd/ospf_abr.h"

DEFINE_HOOK(ospf_ism_change,
	    (struct ospf_interface * oi, int state, int oldstate),
	    (oi, state, oldstate));

/* elect DR and BDR. Refer to RFC2319 section 9.4 */
static struct ospf_neighbor *ospf_dr_election_sub(struct list *routers)
{
	struct listnode *node;
	struct ospf_neighbor *nbr, *max = NULL;

	/* Choose highest router priority.
	   In case of tie, choose highest Router ID. */
	for (ALL_LIST_ELEMENTS_RO(routers, node, nbr)) {
		if (max == NULL)
			max = nbr;
		else {
			if (max->priority < nbr->priority)
				max = nbr;
			else if (max->priority == nbr->priority)
				if (IPV4_ADDR_CMP(&max->router_id,
						  &nbr->router_id)
				    < 0)
					max = nbr;
		}
	}

	return max;
}

static struct ospf_neighbor *ospf_elect_dr(struct ospf_interface *oi,
					   struct list *el_list)
{
	struct list *dr_list;
	struct listnode *node;
	struct ospf_neighbor *nbr, *dr = NULL, *bdr = NULL;

	dr_list = list_new();

	/* Add neighbors to the list. */
	for (ALL_LIST_ELEMENTS_RO(el_list, node, nbr)) {
		/* neighbor declared to be DR. */
		if (NBR_IS_DR(nbr))
			listnode_add(dr_list, nbr);

		/* Preserve neighbor BDR. */
		if (IPV4_ADDR_SAME(&BDR(oi), &nbr->address.u.prefix4))
			bdr = nbr;
	}

	/* Elect Designated Router. */
	if (listcount(dr_list) > 0)
		dr = ospf_dr_election_sub(dr_list);
	else
		dr = bdr;

	/* Set DR to interface. */
	if (dr)
		DR(oi) = dr->address.u.prefix4;
	else
		DR(oi).s_addr = 0;

	list_delete(&dr_list);

	return dr;
}

static struct ospf_neighbor *ospf_elect_bdr(struct ospf_interface *oi,
					    struct list *el_list)
{
	struct list *bdr_list, *no_dr_list;
	struct listnode *node;
	struct ospf_neighbor *nbr, *bdr = NULL;

	bdr_list = list_new();
	no_dr_list = list_new();

	/* Add neighbors to the list. */
	for (ALL_LIST_ELEMENTS_RO(el_list, node, nbr)) {
		/* neighbor declared to be DR. */
		if (NBR_IS_DR(nbr))
			continue;

		/* neighbor declared to be BDR. */
		if (NBR_IS_BDR(nbr))
			listnode_add(bdr_list, nbr);

		listnode_add(no_dr_list, nbr);
	}

	/* Elect Backup Designated Router. */
	if (listcount(bdr_list) > 0)
		bdr = ospf_dr_election_sub(bdr_list);
	else
		bdr = ospf_dr_election_sub(no_dr_list);

	/* Set BDR to interface. */
	if (bdr)
		BDR(oi) = bdr->address.u.prefix4;
	else
		BDR(oi).s_addr = 0;

	list_delete(&bdr_list);
	list_delete(&no_dr_list);

	return bdr;
}

static int ospf_ism_state(struct ospf_interface *oi)
{
	if (IPV4_ADDR_SAME(&DR(oi), &oi->address->u.prefix4))
		return ISM_DR;
	else if (IPV4_ADDR_SAME(&BDR(oi), &oi->address->u.prefix4))
		return ISM_Backup;
	else
		return ISM_DROther;
}

static void ospf_dr_eligible_routers(struct route_table *nbrs,
				     struct list *el_list)
{
	struct route_node *rn;
	struct ospf_neighbor *nbr;

	for (rn = route_top(nbrs); rn; rn = route_next(rn))
		if ((nbr = rn->info) != NULL)
			/* Ignore 0.0.0.0 node*/
			if (nbr->router_id.s_addr != INADDR_ANY)
				/* Is neighbor eligible? */
				if (nbr->priority > 0)
					/* Is neighbor upper 2-Way? */
					if (nbr->state >= NSM_TwoWay)
						listnode_add(el_list, nbr);
}

/* Generate AdjOK? NSM event. */
static void ospf_dr_change(struct ospf *ospf, struct route_table *nbrs)
{
	struct route_node *rn;
	struct ospf_neighbor *nbr;

	for (rn = route_top(nbrs); rn; rn = route_next(rn)) {
		nbr = rn->info;

		if (!nbr)
			continue;

		/*
		 * Ignore 0.0.0.0 node
		 * Is neighbor 2-Way?
		 * Ignore myself
		 */
		if (nbr->router_id.s_addr != INADDR_ANY
		    && nbr->state >= NSM_TwoWay
		    && !IPV4_ADDR_SAME(&nbr->router_id, &ospf->router_id))
			OSPF_NSM_EVENT_SCHEDULE(nbr, NSM_AdjOK);
	}
}

int ospf_dr_election(struct ospf_interface *oi)
{
	struct in_addr old_dr, old_bdr;
	int old_state, new_state;
	struct list *el_list;

	/* backup current values. */
	old_dr = DR(oi);
	old_bdr = BDR(oi);
	old_state = oi->state;

	el_list = list_new();

	/* List eligible routers. */
	ospf_dr_eligible_routers(oi->nbrs, el_list);

	/* First election of DR and BDR. */
	ospf_elect_bdr(oi, el_list);
	ospf_elect_dr(oi, el_list);

	new_state = ospf_ism_state(oi);

	if (IS_DEBUG_OSPF(ism, ISM_STATUS)) {
		zlog_debug("DR-Election[1st]: Backup %pI4", &BDR(oi));
		zlog_debug("DR-Election[1st]: DR     %pI4", &DR(oi));
	}

	if (new_state != old_state
	    && !(new_state == ISM_DROther && old_state < ISM_DROther)) {
		ospf_elect_bdr(oi, el_list);
		ospf_elect_dr(oi, el_list);

		new_state = ospf_ism_state(oi);

		if (IS_DEBUG_OSPF(ism, ISM_STATUS)) {
			zlog_debug("DR-Election[2nd]: Backup %pI4", &BDR(oi));
			zlog_debug("DR-Election[2nd]: DR     %pI4", &DR(oi));
		}
	}

	list_delete(&el_list);

	/* if DR or BDR changes, cause AdjOK? neighbor event. */
	if (!IPV4_ADDR_SAME(&old_dr, &DR(oi))
	    || !IPV4_ADDR_SAME(&old_bdr, &BDR(oi)))
		ospf_dr_change(oi->ospf, oi->nbrs);

	return new_state;
}


void ospf_hello_timer(struct event *thread)
{
	struct ospf_interface *oi;

	oi = EVENT_ARG(thread);
	oi->t_hello = NULL;

	/* Check if the GR hello-delay is active. */
	if (oi->gr.hello_delay.t_grace_send)
		return;

	if (IS_DEBUG_OSPF(ism, ISM_TIMERS))
		zlog_debug("ISM[%s]: Timer (Hello timer expire)", IF_NAME(oi));

	/* Sending hello packet. */
	ospf_hello_send(oi);

	/* Hello timer set. */
	OSPF_HELLO_TIMER_ON(oi);
}

static void ospf_wait_timer(struct event *thread)
{
	struct ospf_interface *oi;

	oi = EVENT_ARG(thread);
	oi->t_wait = NULL;

	if (IS_DEBUG_OSPF(ism, ISM_TIMERS))
		zlog_debug("ISM[%s]: Timer (Wait timer expire)", IF_NAME(oi));

	OSPF_ISM_EVENT_SCHEDULE(oi, ISM_WaitTimer);
}

/* Hook function called after ospf ISM event is occurred. And vty's
   network command invoke this function after making interface
   structure. */
static void ism_timer_set(struct ospf_interface *oi)
{
	switch (oi->state) {
	case ISM_Down:
		/* First entry point of ospf interface state machine. In this
		   state
		   interface parameters must be set to initial values, and
		   timers are
		   reset also. */
		EVENT_OFF(oi->t_hello);
		EVENT_OFF(oi->t_wait);
		EVENT_OFF(oi->t_ls_ack);
		EVENT_OFF(oi->gr.hello_delay.t_grace_send);
		break;
	case ISM_Loopback:
		/* In this state, the interface may be looped back and will be
		   unavailable for regular data traffic. */
		EVENT_OFF(oi->t_hello);
		EVENT_OFF(oi->t_wait);
		EVENT_OFF(oi->t_ls_ack);
		EVENT_OFF(oi->gr.hello_delay.t_grace_send);
		break;
	case ISM_Waiting:
		/* The router is trying to determine the identity of DRouter and
		   BDRouter. The router begin to receive and send Hello Packets.
		   */
		/* send first hello immediately */
		OSPF_ISM_TIMER_MSEC_ON(oi->t_hello, ospf_hello_timer, 1);
		OSPF_ISM_TIMER_ON(oi->t_wait, ospf_wait_timer,
				  OSPF_IF_PARAM(oi, v_wait));
		EVENT_OFF(oi->t_ls_ack);
		break;
	case ISM_PointToPoint:
		/* The interface connects to a physical Point-to-point network
		   or
		   virtual link. The router attempts to form an adjacency with
		   neighboring router. Hello packets are also sent. */
		/* send first hello immediately */
		OSPF_ISM_TIMER_MSEC_ON(oi->t_hello, ospf_hello_timer, 1);
		EVENT_OFF(oi->t_wait);
		OSPF_ISM_TIMER_ON(oi->t_ls_ack, ospf_ls_ack_timer,
				  oi->v_ls_ack);
		break;
	case ISM_DROther:
		/* The network type of the interface is broadcast or NBMA
		   network,
		   and the router itself is neither Designated Router nor
		   Backup Designated Router. */
		OSPF_HELLO_TIMER_ON(oi);
		EVENT_OFF(oi->t_wait);
		OSPF_ISM_TIMER_ON(oi->t_ls_ack, ospf_ls_ack_timer,
				  oi->v_ls_ack);
		break;
	case ISM_Backup:
		/* The network type of the interface is broadcast os NBMA
		   network,
		   and the router is Backup Designated Router. */
		OSPF_HELLO_TIMER_ON(oi);
		EVENT_OFF(oi->t_wait);
		OSPF_ISM_TIMER_ON(oi->t_ls_ack, ospf_ls_ack_timer,
				  oi->v_ls_ack);
		break;
	case ISM_DR:
		/* The network type of the interface is broadcast or NBMA
		   network,
		   and the router is Designated Router. */
		OSPF_HELLO_TIMER_ON(oi);
		EVENT_OFF(oi->t_wait);
		OSPF_ISM_TIMER_ON(oi->t_ls_ack, ospf_ls_ack_timer,
				  oi->v_ls_ack);
		break;
	}
}

static int ism_interface_up(struct ospf_interface *oi)
{
	int next_state = 0;

	/* if network type is point-to-point, Point-to-MultiPoint or virtual
	   link,
	   the state transitions to Point-to-Point. */
	if (oi->type == OSPF_IFTYPE_POINTOPOINT
	    || oi->type == OSPF_IFTYPE_POINTOMULTIPOINT
	    || oi->type == OSPF_IFTYPE_VIRTUALLINK)
		next_state = ISM_PointToPoint;
	/* Else if the router is not eligible to DR, the state transitions to
	   DROther. */
	else if (PRIORITY(oi) == 0) /* router is eligible? */
		next_state = ISM_DROther;
	else
		/* Otherwise, the state transitions to Waiting. */
		next_state = ISM_Waiting;

	if (oi->type == OSPF_IFTYPE_NBMA)
		ospf_nbr_nbma_if_update(oi->ospf, oi);

	/*  ospf_ism_event (t); */
	return next_state;
}

static int ism_loop_ind(struct ospf_interface *oi)
{
	/* call ism_interface_down. */
	/* ret = ism_interface_down (oi); */

	return 0;
}

/* Interface down event handler. */
static int ism_interface_down(struct ospf_interface *oi)
{
	ospf_if_cleanup(oi);
	return 0;
}


static int ism_backup_seen(struct ospf_interface *oi)
{
	return ospf_dr_election(oi);
}

static int ism_wait_timer(struct ospf_interface *oi)
{
	return ospf_dr_election(oi);
}

static int ism_neighbor_change(struct ospf_interface *oi)
{
	return ospf_dr_election(oi);
}

static int ism_ignore(struct ospf_interface *oi)
{
	if (IS_DEBUG_OSPF(ism, ISM_EVENTS))
		zlog_debug("ISM[%s]: ism_ignore called", IF_NAME(oi));

	return 0;
}

/* Interface State Machine */
const struct {
	int (*func)(struct ospf_interface *);
	int next_state;
} ISM[OSPF_ISM_STATE_MAX][OSPF_ISM_EVENT_MAX] = {
	{
		/* DependUpon: dummy state. */
		{ism_ignore, ISM_DependUpon}, /* NoEvent        */
		{ism_ignore, ISM_DependUpon}, /* InterfaceUp    */
		{ism_ignore, ISM_DependUpon}, /* WaitTimer      */
		{ism_ignore, ISM_DependUpon}, /* BackupSeen     */
		{ism_ignore, ISM_DependUpon}, /* NeighborChange */
		{ism_ignore, ISM_DependUpon}, /* LoopInd        */
		{ism_ignore, ISM_DependUpon}, /* UnloopInd      */
		{ism_ignore, ISM_DependUpon}, /* InterfaceDown  */
	},
	{
		/* Down:*/
		{ism_ignore, ISM_DependUpon},       /* NoEvent        */
		{ism_interface_up, ISM_DependUpon}, /* InterfaceUp    */
		{ism_ignore, ISM_Down},		    /* WaitTimer      */
		{ism_ignore, ISM_Down},		    /* BackupSeen     */
		{ism_ignore, ISM_Down},		    /* NeighborChange */
		{ism_loop_ind, ISM_Loopback},       /* LoopInd        */
		{ism_ignore, ISM_Down},		    /* UnloopInd      */
		{ism_interface_down, ISM_Down},     /* InterfaceDown  */
	},
	{
		/* Loopback: */
		{ism_ignore, ISM_DependUpon},   /* NoEvent        */
		{ism_ignore, ISM_Loopback},     /* InterfaceUp    */
		{ism_ignore, ISM_Loopback},     /* WaitTimer      */
		{ism_ignore, ISM_Loopback},     /* BackupSeen     */
		{ism_ignore, ISM_Loopback},     /* NeighborChange */
		{ism_ignore, ISM_Loopback},     /* LoopInd        */
		{ism_ignore, ISM_Down},		/* UnloopInd      */
		{ism_interface_down, ISM_Down}, /* InterfaceDown  */
	},
	{
		/* Waiting: */
		{ism_ignore, ISM_DependUpon},      /* NoEvent        */
		{ism_ignore, ISM_Waiting},	 /* InterfaceUp    */
		{ism_wait_timer, ISM_DependUpon},  /* WaitTimer      */
		{ism_backup_seen, ISM_DependUpon}, /* BackupSeen     */
		{ism_ignore, ISM_Waiting},	 /* NeighborChange */
		{ism_loop_ind, ISM_Loopback},      /* LoopInd        */
		{ism_ignore, ISM_Waiting},	 /* UnloopInd      */
		{ism_interface_down, ISM_Down},    /* InterfaceDown  */
	},
	{
		/* Point-to-Point: */
		{ism_ignore, ISM_DependUpon},   /* NoEvent        */
		{ism_ignore, ISM_PointToPoint}, /* InterfaceUp    */
		{ism_ignore, ISM_PointToPoint}, /* WaitTimer      */
		{ism_ignore, ISM_PointToPoint}, /* BackupSeen     */
		{ism_ignore, ISM_PointToPoint}, /* NeighborChange */
		{ism_loop_ind, ISM_Loopback},   /* LoopInd        */
		{ism_ignore, ISM_PointToPoint}, /* UnloopInd      */
		{ism_interface_down, ISM_Down}, /* InterfaceDown  */
	},
	{
		/* DROther: */
		{ism_ignore, ISM_DependUpon},	  /* NoEvent        */
		{ism_ignore, ISM_DROther},	     /* InterfaceUp    */
		{ism_ignore, ISM_DROther},	     /* WaitTimer      */
		{ism_ignore, ISM_DROther},	     /* BackupSeen     */
		{ism_neighbor_change, ISM_DependUpon}, /* NeighborChange */
		{ism_loop_ind, ISM_Loopback},	  /* LoopInd        */
		{ism_ignore, ISM_DROther},	     /* UnloopInd      */
		{ism_interface_down, ISM_Down},	/* InterfaceDown  */
	},
	{
		/* Backup: */
		{ism_ignore, ISM_DependUpon},	  /* NoEvent        */
		{ism_ignore, ISM_Backup},	      /* InterfaceUp    */
		{ism_ignore, ISM_Backup},	      /* WaitTimer      */
		{ism_ignore, ISM_Backup},	      /* BackupSeen     */
		{ism_neighbor_change, ISM_DependUpon}, /* NeighborChange */
		{ism_loop_ind, ISM_Loopback},	  /* LoopInd        */
		{ism_ignore, ISM_Backup},	      /* UnloopInd      */
		{ism_interface_down, ISM_Down},	/* InterfaceDown  */
	},
	{
		/* DR: */
		{ism_ignore, ISM_DependUpon},	  /* NoEvent        */
		{ism_ignore, ISM_DR},		       /* InterfaceUp    */
		{ism_ignore, ISM_DR},		       /* WaitTimer      */
		{ism_ignore, ISM_DR},		       /* BackupSeen     */
		{ism_neighbor_change, ISM_DependUpon}, /* NeighborChange */
		{ism_loop_ind, ISM_Loopback},	  /* LoopInd        */
		{ism_ignore, ISM_DR},		       /* UnloopInd      */
		{ism_interface_down, ISM_Down},	/* InterfaceDown  */
	},
};

static const char *const ospf_ism_event_str[] = {
	"NoEvent",	"InterfaceUp", "WaitTimer", "BackupSeen",
	"NeighborChange", "LoopInd",     "UnLoopInd", "InterfaceDown",
};

static void ism_change_state(struct ospf_interface *oi, int state)
{
	int old_state;
	struct ospf_lsa *lsa;

	/* Logging change of state. */
	if (IS_DEBUG_OSPF(ism, ISM_STATUS))
		zlog_debug("ISM[%s]: State change %s -> %s", IF_NAME(oi),
			   lookup_msg(ospf_ism_state_msg, oi->state, NULL),
			   lookup_msg(ospf_ism_state_msg, state, NULL));

	old_state = oi->state;
	oi->state = state;
	oi->state_change++;

	hook_call(ospf_ism_change, oi, state, old_state);

	/* Set multicast memberships appropriately for new state. */
	ospf_if_set_multicast(oi);

	if (old_state == ISM_Down || state == ISM_Down)
		ospf_check_abr_status(oi->ospf);

	/* Originate router-LSA. */
	if (state == ISM_Down) {
		if (oi->area->act_ints > 0)
			oi->area->act_ints--;
	} else if (old_state == ISM_Down)
		oi->area->act_ints++;

	/* schedule router-LSA originate. */
	ospf_router_lsa_update_area(oi->area);

	/* Originate network-LSA. */
	if (old_state != ISM_DR && state == ISM_DR)
		ospf_network_lsa_update(oi);
	else if (old_state == ISM_DR && state != ISM_DR) {
		/* Free self originated network LSA. */
		lsa = oi->network_lsa_self;
		if (lsa)
			ospf_lsa_flush_area(lsa, oi->area);

		ospf_lsa_unlock(&oi->network_lsa_self);
		oi->network_lsa_self = NULL;
	}

	ospf_opaque_ism_change(oi, old_state);

	/* Check area border status.  */
	ospf_check_abr_status(oi->ospf);
}

/* Execute ISM event process. */
void ospf_ism_event(struct event *thread)
{
	int event;
	int next_state;
	struct ospf_interface *oi;

	oi = EVENT_ARG(thread);
	event = EVENT_VAL(thread);

	/* Call function. */
	next_state = (*(ISM[oi->state][event].func))(oi);

	if (!next_state)
		next_state = ISM[oi->state][event].next_state;

	if (IS_DEBUG_OSPF(ism, ISM_EVENTS))
		zlog_debug("ISM[%s]: %s (%s)", IF_NAME(oi),
			   lookup_msg(ospf_ism_state_msg, oi->state, NULL),
			   ospf_ism_event_str[event]);

	/* If state is changed. */
	if (next_state != oi->state)
		ism_change_state(oi, next_state);

	/* Make sure timer is set. */
	ism_timer_set(oi);
}
