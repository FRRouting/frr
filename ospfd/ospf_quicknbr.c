// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2026	ATCorp
 *			Nathan Bahr
 */

#include <zebra.h>
#include "lib/if.h"
#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_quicknbr.h"

static void ospf_qn_wait(struct event *evt)
{
	struct ospf_interface *oi;

	oi = evt->arg;
	/* Only meaningful while the interface is in ISM_Waiting. */
	if (oi->state != ISM_Waiting) {
		if (IS_DEBUG_OSPF_QNBR)
			zlog_debug("%s: stopping qnbr wait: if=%s state=%s", __func__,
				   oi->ifp->name, lookup_msg(ospf_ism_state_msg, oi->state, NULL));
		oi->t_qn_wait = NULL;
		return;
	}
	if (oi->num_q_nbrs) {
		event_add_timer_msec(master, ospf_qn_wait, oi, 100, &oi->t_qn_wait);
		return;
	}
	/* no more quick neighbors, so go ahead and drop the interface out of waiting */
	if (IS_DEBUG_OSPF_QNBR)
		zlog_debug("%s: all qnbr router-ids learned, firing ISM_WaitTimer: if=%s",
			   __func__, oi->ifp->name);
	oi->t_qn_wait = NULL;
	OSPF_ISM_EVENT_EXECUTE(oi, ISM_WaitTimer);
}

/*
 * Add the neighbor immediately if not already found on the supplied interface.
 * This may add a new neighbor to the neighbor list without a router-id and other
 * assumed information, such as priority.
 * The new neighbor will be artificially pushed through the NSM states until
 * ExStart is reached.
 * This handles the case of the interface being in the waiting state and will take over
 * the waiting timer and allow the interface to go to the next state once all quick neighbors
 * have been officially seen and router-ids learned.
 */
void ospf_qn_add(struct ospf_interface *oi, struct in_addr *endpoint)
{
	struct ospf_neighbor *nbr;

	if (!oi || !endpoint)
		return;

	/* Don't try to force neighbor/ISM/NSM transitions on a down interface. */
	if (!ospf_if_is_up(oi) || oi->state == ISM_Down || oi->state == ISM_Loopback)
		return;

	nbr = ospf_nbr_lookup_by_addr(oi->nbrs, endpoint);
	if (!nbr || nbr->state <= NSM_TwoWay) {
		if (IS_DEBUG_OSPF_QNBR)
			zlog_debug("%s: Reachable endpoint%s, link=%s, endpoint=%pI4", __func__,
				   (nbr ? "" : " (new)"), oi->ifp->name, endpoint);

		if (!nbr)
			nbr = ospf_qnbr_get(oi, endpoint);
		if (!nbr)
			return;

		/* We want the neighbor to be in the two-way state */
		/*
		 * Must fake a hello if not yet at Init. If we're already at Init (e.g.
		 * rapid BFD bounce mid-transition), re-firing HelloReceived is harmless:
		 * NSM handles Init+HelloReceived as a no-op, but it may re-arm t_qn_wait.
		 */
		if (nbr->state <= NSM_Init)
			OSPF_NSM_EVENT_EXECUTE(nbr, NSM_HelloReceived);
		/* Now in init state, move to two-way */
		OSPF_NSM_EVENT_EXECUTE(nbr, NSM_TwoWayReceived);

		/* If the interface is still waiting, we need to push it out of waiting state
		 * in order for the new neighbor to go to ExStart.
		 * We want to wait until we have learned the router-ids of all of the quick
		 * neighbors though first, so start a timer to check.
		 */
		if (oi->state == ISM_Waiting) {
			if (!oi->t_qn_wait) {
				if (IS_DEBUG_OSPF_QNBR)
					zlog_debug("%s: starting qnbr wait (keeping t_wait backstop): if=%s",
						   __func__, oi->ifp->name);
				event_add_timer_msec(master, ospf_qn_wait, oi, 100, &oi->t_qn_wait);
			}
		}

		/* Since DR election won't work without router-ids, push the neighbor to ExStart
		 * artificially by saying that forming an adjacency is ok.
		 */
		OSPF_NSM_EVENT_EXECUTE(nbr, NSM_AdjOK);
	} else if (IS_DEBUG_OSPF_QNBR)
		zlog_debug("%s: Reachable endpoint already has full adjacency, link=%s, endpoint=%pI4",
			   __func__, oi->ifp->name, endpoint);
}
