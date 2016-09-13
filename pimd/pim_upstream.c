/*
  PIM for Quagga
  Copyright (C) 2008  Everton da Silva Marques

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  General Public License for more details.
  
  You should have received a copy of the GNU General Public License
  along with this program; see the file COPYING; if not, write to the
  Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
  MA 02110-1301 USA
  
*/

#include <zebra.h>

#include "zebra/rib.h"

#include "log.h"
#include "zclient.h"
#include "memory.h"
#include "thread.h"
#include "linklist.h"
#include "vty.h"
#include "plist.h"

#include "pimd.h"
#include "pim_pim.h"
#include "pim_str.h"
#include "pim_time.h"
#include "pim_iface.h"
#include "pim_join.h"
#include "pim_zlookup.h"
#include "pim_upstream.h"
#include "pim_ifchannel.h"
#include "pim_neighbor.h"
#include "pim_rpf.h"
#include "pim_zebra.h"
#include "pim_oil.h"
#include "pim_macro.h"
#include "pim_rp.h"
#include "pim_br.h"
#include "pim_register.h"

static void join_timer_start(struct pim_upstream *up);
static void pim_upstream_update_assert_tracking_desired(struct pim_upstream *up);

/*
 * A (*,G) or a (*,*) is going away
 * remove the parent pointer from
 * those pointing at us
 */
static void
pim_upstream_remove_children (struct pim_upstream *up)
{
  struct listnode *ch_node;
  struct pim_upstream *child;

  // Basic sanity, (*,*) not currently supported
  if ((up->sg.src.s_addr == INADDR_ANY) &&
      (up->sg.grp.s_addr == INADDR_ANY))
    return;

  // Basic sanity (S,G) have no children
  if ((up->sg.src.s_addr != INADDR_ANY) &&
      (up->sg.grp.s_addr != INADDR_ANY))
    return;

  for (ALL_LIST_ELEMENTS_RO (qpim_upstream_list, ch_node, child))
    {
      if (child->parent == up)
        child->parent = NULL;
    }
}

/*
 * A (*,G) or a (*,*) is being created
 * Find the children that would point
 * at us.
 */
static void
pim_upstream_find_new_children (struct pim_upstream *up)
{
  struct pim_upstream *child;
  struct listnode *ch_node;

  if ((up->sg.src.s_addr != INADDR_ANY) &&
      (up->sg.grp.s_addr != INADDR_ANY))
    return;

  if ((up->sg.src.s_addr == INADDR_ANY) &&
      (up->sg.grp.s_addr == INADDR_ANY))
    return;

  for (ALL_LIST_ELEMENTS_RO (qpim_upstream_list, ch_node, child))
    {
      if ((up->sg.grp.s_addr != INADDR_ANY) &&
          (child->sg.grp.s_addr == up->sg.grp.s_addr) &&
	  (child != up))
        child->parent = up;
    }
}

/*
 * If we have a (*,*) || (S,*) there is no parent
 * If we have a (S,G), find the (*,G)
 * If we have a (*,G), find the (*,*)
 */
static struct pim_upstream *
pim_upstream_find_parent (struct prefix_sg *sg)
{
  struct prefix_sg any = *sg;

  // (*,*) || (S,*)
  if (((sg->src.s_addr == INADDR_ANY) &&
       (sg->grp.s_addr == INADDR_ANY)) ||
      ((sg->src.s_addr != INADDR_ANY) &&
       (sg->grp.s_addr == INADDR_ANY)))
    return NULL;

  // (S,G)
  if ((sg->src.s_addr != INADDR_ANY) &&
      (sg->grp.s_addr != INADDR_ANY))
    {
      any.src.s_addr = INADDR_ANY;
      return pim_upstream_find (&any);
    }

  // (*,G)
  any.grp.s_addr = INADDR_ANY;
  return pim_upstream_find (&any);
}

void pim_upstream_free(struct pim_upstream *up)
{
  XFREE(MTYPE_PIM_UPSTREAM, up);
}

static void upstream_channel_oil_detach(struct pim_upstream *up)
{
  if (up->channel_oil) {
    pim_channel_oil_del(up->channel_oil);
    up->channel_oil = NULL;
  }
}

void pim_upstream_delete(struct pim_upstream *up)
{
  THREAD_OFF(up->t_join_timer);
  THREAD_OFF(up->t_ka_timer);
  THREAD_OFF(up->t_rs_timer);

  pim_upstream_remove_children (up);
  pim_mroute_del (up->channel_oil);
  upstream_channel_oil_detach(up);

  /*
    notice that listnode_delete() can't be moved
    into pim_upstream_free() because the later is
    called by list_delete_all_node()
  */
  listnode_delete(qpim_upstream_list, up);

  pim_upstream_free(up);
}

void
pim_upstream_send_join (struct pim_upstream *up)
{
  if (PIM_DEBUG_PIM_TRACE) {
    char rpf_str[100];
    pim_addr_dump("<rpf?>", &up->rpf.rpf_addr, rpf_str, sizeof(rpf_str));
    zlog_debug ("%s: RPF'%s=%s(%s) for Interface %s", __PRETTY_FUNCTION__,
		pim_str_sg_dump (&up->sg), rpf_str, pim_upstream_state2str (up->join_state),
		up->rpf.source_nexthop.interface->name);
    if (pim_rpf_addr_is_inaddr_any(&up->rpf)) {
      zlog_debug("%s: can't send join upstream: RPF'%s=%s",
		 __PRETTY_FUNCTION__,
		 pim_str_sg_dump (&up->sg), rpf_str);
      /* warning only */
    }
  }

  /* send Join(S,G) to the current upstream neighbor */
  pim_joinprune_send(up->rpf.source_nexthop.interface,
  		     up->rpf.rpf_addr.u.prefix4,
		     &up->sg,
		     1 /* join */);
}

static int on_join_timer(struct thread *t)
{
  struct pim_upstream *up;

  zassert(t);
  up = THREAD_ARG(t);
  zassert(up);

  up->t_join_timer = NULL;

  /*
   * In the case of a HFR we will not ahve anyone to send this to.
   */
  if (PIM_UPSTREAM_FLAG_TEST_FHR(up->flags))
    return 0;

  /*
   * Don't send the join if the outgoing interface is a loopback
   * But since this might change leave the join timer running
   */
  if (!if_is_loopback (up->rpf.source_nexthop.interface))
    pim_upstream_send_join (up);

  join_timer_start(up);

  return 0;
}

static void join_timer_start(struct pim_upstream *up)
{
  if (PIM_DEBUG_PIM_EVENTS) {
    zlog_debug("%s: starting %d sec timer for upstream (S,G)=%s",
	       __PRETTY_FUNCTION__,
	       qpim_t_periodic,
	       pim_str_sg_dump (&up->sg));
  }

  THREAD_OFF (up->t_join_timer);
  THREAD_TIMER_ON(master, up->t_join_timer,
		  on_join_timer,
		  up, qpim_t_periodic);
}

void pim_upstream_join_timer_restart(struct pim_upstream *up)
{
  THREAD_OFF(up->t_join_timer);
  join_timer_start(up);
}

static void pim_upstream_join_timer_restart_msec(struct pim_upstream *up,
						 int interval_msec)
{
  if (PIM_DEBUG_PIM_EVENTS) {
    zlog_debug("%s: restarting %d msec timer for upstream (S,G)=%s",
	       __PRETTY_FUNCTION__,
	       interval_msec,
	       pim_str_sg_dump (&up->sg));
  }

  THREAD_OFF(up->t_join_timer);
  THREAD_TIMER_MSEC_ON(master, up->t_join_timer,
		       on_join_timer,
		       up, interval_msec);
}

void pim_upstream_join_suppress(struct pim_upstream *up,
				struct in_addr rpf_addr,
				int holdtime)
{
  long t_joinsuppress_msec;
  long join_timer_remain_msec;

  t_joinsuppress_msec = MIN(pim_if_t_suppressed_msec(up->rpf.source_nexthop.interface),
			    1000 * holdtime);

  join_timer_remain_msec = pim_time_timer_remain_msec(up->t_join_timer);

  if (PIM_DEBUG_PIM_TRACE) {
    char rpf_str[100];
    pim_inet4_dump("<rpf?>", rpf_addr, rpf_str, sizeof(rpf_str));
    zlog_debug("%s %s: detected Join%s to RPF'(S,G)=%s: join_timer=%ld msec t_joinsuppress=%ld msec",
	       __FILE__, __PRETTY_FUNCTION__, 
	       pim_str_sg_dump (&up->sg),
	       rpf_str,
	       join_timer_remain_msec, t_joinsuppress_msec);
  }

  if (join_timer_remain_msec < t_joinsuppress_msec) {
    if (PIM_DEBUG_PIM_TRACE) {
      zlog_debug("%s %s: suppressing Join(S,G)=%s for %ld msec",
		 __FILE__, __PRETTY_FUNCTION__, 
		 pim_str_sg_dump (&up->sg), t_joinsuppress_msec);
    }

    pim_upstream_join_timer_restart_msec(up, t_joinsuppress_msec);
  }
}

void pim_upstream_join_timer_decrease_to_t_override(const char *debug_label,
						    struct pim_upstream *up,
						    struct in_addr rpf_addr)
{
  long join_timer_remain_msec;
  int t_override_msec;

  join_timer_remain_msec = pim_time_timer_remain_msec(up->t_join_timer);
  t_override_msec = pim_if_t_override_msec(up->rpf.source_nexthop.interface);

  if (PIM_DEBUG_PIM_TRACE) {
    char rpf_str[100];
    pim_inet4_dump("<rpf?>", rpf_addr, rpf_str, sizeof(rpf_str));
    zlog_debug("%s: to RPF'%s=%s: join_timer=%ld msec t_override=%d msec",
	       debug_label,
	       pim_str_sg_dump (&up->sg), rpf_str,
	       join_timer_remain_msec, t_override_msec);
  }
    
  if (join_timer_remain_msec > t_override_msec) {
    if (PIM_DEBUG_PIM_TRACE) {
      zlog_debug("%s: decreasing (S,G)=%s join timer to t_override=%d msec",
		 debug_label,
		 pim_str_sg_dump (&up->sg),
		 t_override_msec);
    }

    pim_upstream_join_timer_restart_msec(up, t_override_msec);
  }
}

static void forward_on(struct pim_upstream *up)
{
  struct listnode      *ifnode;
  struct listnode      *ifnextnode;
  struct listnode      *chnode;
  struct listnode      *chnextnode;
  struct interface     *ifp;
  struct pim_interface *pim_ifp;
  struct pim_ifchannel *ch;

  /* scan all interfaces */
  for (ALL_LIST_ELEMENTS (vrf_iflist (VRF_DEFAULT), ifnode, ifnextnode, ifp)) {
    pim_ifp = ifp->info;
    if (!pim_ifp)
      continue;

    /* scan per-interface (S,G) state */
    for (ALL_LIST_ELEMENTS(pim_ifp->pim_ifchannel_list, chnode, chnextnode, ch)) {

      if (ch->upstream != up)
	continue;

      if (pim_macro_chisin_oiflist(ch))
	pim_forward_start(ch);

    } /* scan iface channel list */
  } /* scan iflist */
}

static void forward_off(struct pim_upstream *up)
{
  struct listnode      *ifnode;
  struct listnode      *ifnextnode;
  struct listnode      *chnode;
  struct listnode      *chnextnode;
  struct interface     *ifp;
  struct pim_interface *pim_ifp;
  struct pim_ifchannel *ch;

  /* scan all interfaces */
  for (ALL_LIST_ELEMENTS (vrf_iflist (VRF_DEFAULT), ifnode, ifnextnode, ifp)) {
    pim_ifp = ifp->info;
    if (!pim_ifp)
      continue;

    /* scan per-interface (S,G) state */
    for (ALL_LIST_ELEMENTS(pim_ifp->pim_ifchannel_list, chnode, chnextnode, ch)) {

      if (ch->upstream != up)
	continue;

      pim_forward_stop(ch);

    } /* scan iface channel list */
  } /* scan iflist */
}

static int
pim_upstream_could_register (struct pim_upstream *up)
{
  struct pim_interface *pim_ifp = up->rpf.source_nexthop.interface->info;

  if (pim_ifp && PIM_I_am_DR (pim_ifp) &&
      pim_if_connected_to_source (up->rpf.source_nexthop.interface, up->sg.src))
    return 1;

  return 0;
}

void
pim_upstream_switch(struct pim_upstream *up,
		    enum pim_upstream_state new_state)
{
  enum pim_upstream_state old_state = up->join_state;

  if (PIM_DEBUG_PIM_EVENTS) {
    zlog_debug("%s: PIM_UPSTREAM_%s: (S,G) old: %s new: %s",
	       __PRETTY_FUNCTION__,
	       pim_str_sg_dump (&up->sg),
	       pim_upstream_state2str (up->join_state),
	       pim_upstream_state2str (new_state));
  }

  /*
   * This code still needs work.
   */
  switch (up->join_state)
    {
    case PIM_UPSTREAM_PRUNE:
      if (!PIM_UPSTREAM_FLAG_TEST_FHR(up->flags))
        {
          up->join_state       = new_state;
          up->state_transition = pim_time_monotonic_sec ();
        }
      break;
    case PIM_UPSTREAM_JOIN_PENDING:
      break;
    case PIM_UPSTREAM_NOTJOINED:
    case PIM_UPSTREAM_JOINED:
      up->join_state       = new_state;
      up->state_transition = pim_time_monotonic_sec();

      break;
    }

  pim_upstream_update_assert_tracking_desired(up);

  if (new_state == PIM_UPSTREAM_JOINED) {
    if (old_state != PIM_UPSTREAM_JOINED)
      {
        int old_fhr = PIM_UPSTREAM_FLAG_TEST_FHR(up->flags);
        forward_on(up);
	if (pim_upstream_could_register (up))
	  {
            PIM_UPSTREAM_FLAG_SET_FHR(up->flags);
            if (!old_fhr && PIM_UPSTREAM_FLAG_TEST_SRC_STREAM(up->flags))
              {
                pim_upstream_keep_alive_timer_start (up, qpim_keep_alive_time);
	        pim_channel_add_oif (up->channel_oil, pim_regiface, PIM_OIF_FLAG_PROTO_PIM);
              }
	  }
	else
          {
	    pim_upstream_send_join (up);
	    join_timer_start (up);
	  }
      }
    else
      {
        forward_on (up);
      }
  }
  else {
    forward_off(up);
    pim_joinprune_send(up->rpf.source_nexthop.interface,
		       up->rpf.rpf_addr.u.prefix4,
		       &up->sg,
		       0 /* prune */);
    if (up->t_join_timer)
      THREAD_OFF(up->t_join_timer);
  }
}

static struct pim_upstream *pim_upstream_new(struct prefix_sg *sg,
					     struct interface *incoming)
{
  struct pim_upstream *up;
  enum pim_rpf_result rpf_result;

  up = XCALLOC(MTYPE_PIM_UPSTREAM, sizeof(*up));
  if (!up) {
    zlog_err("%s: PIM XCALLOC(%zu) failure",
	     __PRETTY_FUNCTION__, sizeof(*up));
    return NULL;
  }
  
  up->sg                          = *sg;
  if (!pim_rp_set_upstream_addr (&up->upstream_addr, sg->src, sg->grp))
    {
      if (PIM_DEBUG_PIM_TRACE)
	zlog_debug("%s: Received a (*,G) with no RP configured", __PRETTY_FUNCTION__);

      XFREE (MTYPE_PIM_UPSTREAM, up);
      return NULL;
    }

  up->parent                     = pim_upstream_find_parent (sg);
  pim_upstream_find_new_children (up);
  up->flags                      = 0;
  up->ref_count                  = 1;
  up->t_join_timer               = NULL;
  up->t_ka_timer                 = NULL;
  up->t_rs_timer                 = NULL;
  up->join_state                 = 0;
  up->state_transition           = pim_time_monotonic_sec();
  up->channel_oil                = NULL;
  up->sptbit                     = PIM_UPSTREAM_SPTBIT_FALSE;

  up->rpf.source_nexthop.interface                = NULL;
  up->rpf.source_nexthop.mrib_nexthop_addr.family = AF_INET;
  up->rpf.source_nexthop.mrib_nexthop_addr.u.prefix4.s_addr = PIM_NET_INADDR_ANY;
  up->rpf.source_nexthop.mrib_metric_preference   = qpim_infinite_assert_metric.metric_preference;
  up->rpf.source_nexthop.mrib_route_metric        = qpim_infinite_assert_metric.route_metric;
  up->rpf.rpf_addr.family                         = AF_INET;
  up->rpf.rpf_addr.u.prefix4.s_addr               = PIM_NET_INADDR_ANY;

  rpf_result = pim_rpf_update(up, NULL);
  if (rpf_result == PIM_RPF_FAILURE) {
    XFREE(MTYPE_PIM_UPSTREAM, up);
    return NULL;
  }

  listnode_add(qpim_upstream_list, up);

  return up;
}

/*
 * For a given sg, find any non * source
 */
struct pim_upstream *pim_upstream_find_non_any (struct prefix_sg *sg)
{
  struct listnode *up_node;
  struct prefix_sg any = *sg;
  struct pim_upstream *up;

  any.src.s_addr = INADDR_ANY;

  for (ALL_LIST_ELEMENTS_RO (qpim_upstream_list, up_node, up))
    {
      if ((any.grp.s_addr == up->sg.grp.s_addr) &&
          (up->sg.src.s_addr != any.src.s_addr))
        return up;
    }

  return NULL;
}

struct pim_upstream *pim_upstream_find(struct prefix_sg *sg)
{
  struct listnode     *up_node;
  struct pim_upstream *up;

  for (ALL_LIST_ELEMENTS_RO(qpim_upstream_list, up_node, up)) {
    if ((sg->grp.s_addr == up->sg.grp.s_addr) &&
	(sg->src.s_addr == up->sg.src.s_addr))
      return up;
  }

  return NULL;
}

struct pim_upstream *pim_upstream_add(struct prefix_sg *sg,
				      struct interface *incoming)
{
  struct pim_upstream *up;

  up = pim_upstream_find(sg);
  if (up) {
    ++up->ref_count;
  }
  else {
    up = pim_upstream_new(sg, incoming);
  }

  return up;
}

void pim_upstream_del(struct pim_upstream *up)
{
  --up->ref_count;

  if (up->ref_count < 1) {
    pim_upstream_delete(up);
  }
}

static int
pim_upstream_evaluate_join_desired_interface (struct pim_upstream *up,
					      struct pim_ifchannel *ch)
{
  struct pim_upstream *parent = up->parent;

  if (ch->upstream == up)
    {
      if (!pim_macro_ch_lost_assert(ch) && pim_macro_chisin_joins_or_include(ch))
	return 1;
    }
  /*
   * joins (*,G)
   */
  if (parent && ch->upstream == parent)
    {
      if (!pim_macro_ch_lost_assert (ch) && pim_macro_chisin_joins_or_include (ch))
	return 1;
    }

  return 0;
}

/*
  Evaluate JoinDesired(S,G):

  JoinDesired(S,G) is true if there is a downstream (S,G) interface I
  in the set:

  inherited_olist(S,G) =
  joins(S,G) (+) pim_include(S,G) (-) lost_assert(S,G)

  JoinDesired(S,G) may be affected by changes in the following:

  pim_ifp->primary_address
  pim_ifp->pim_dr_addr
  ch->ifassert_winner_metric
  ch->ifassert_winner
  ch->local_ifmembership 
  ch->ifjoin_state
  ch->upstream->rpf.source_nexthop.mrib_metric_preference
  ch->upstream->rpf.source_nexthop.mrib_route_metric
  ch->upstream->rpf.source_nexthop.interface

  See also pim_upstream_update_join_desired() below.
 */
int pim_upstream_evaluate_join_desired(struct pim_upstream *up)
{
  struct listnode      *ifnode;
  struct listnode      *ifnextnode;
  struct listnode      *chnode;
  struct listnode      *chnextnode;
  struct interface     *ifp;
  struct pim_interface *pim_ifp;
  struct pim_ifchannel *ch;
  int                  ret = 0;

  /* scan all interfaces */
  for (ALL_LIST_ELEMENTS (vrf_iflist (VRF_DEFAULT), ifnode, ifnextnode, ifp)) {
    pim_ifp = ifp->info;
    if (!pim_ifp)
      continue;

    /* scan per-interface (S,G) state */
    for (ALL_LIST_ELEMENTS(pim_ifp->pim_ifchannel_list, chnode, chnextnode, ch))
      {
	ret += pim_upstream_evaluate_join_desired_interface (up, ch);
      } /* scan iface channel list */
  } /* scan iflist */

  return ret; /* false */
}

/*
  See also pim_upstream_evaluate_join_desired() above.
*/
void pim_upstream_update_join_desired(struct pim_upstream *up)
{
  int was_join_desired; /* boolean */
  int is_join_desired; /* boolean */

  was_join_desired = PIM_UPSTREAM_FLAG_TEST_DR_JOIN_DESIRED(up->flags);

  is_join_desired = pim_upstream_evaluate_join_desired(up);
  if (is_join_desired)
    PIM_UPSTREAM_FLAG_SET_DR_JOIN_DESIRED(up->flags);
  else
    PIM_UPSTREAM_FLAG_UNSET_DR_JOIN_DESIRED(up->flags);

  /* switched from false to true */
  if (is_join_desired && !was_join_desired) {
    pim_upstream_switch(up, PIM_UPSTREAM_JOINED);
    return;
  }
      
  /* switched from true to false */
  if (!is_join_desired && was_join_desired) {
    pim_upstream_switch(up, PIM_UPSTREAM_NOTJOINED);
    return;
  }
}

/*
  RFC 4601 4.5.7. Sending (S,G) Join/Prune Messages
  Transitions from Joined State
  RPF'(S,G) GenID changes

  The upstream (S,G) state machine remains in Joined state.  If the
  Join Timer is set to expire in more than t_override seconds, reset
  it so that it expires after t_override seconds.
*/
void pim_upstream_rpf_genid_changed(struct in_addr neigh_addr)
{
  struct listnode     *up_node;
  struct listnode     *up_nextnode;
  struct pim_upstream *up;

  /*
    Scan all (S,G) upstreams searching for RPF'(S,G)=neigh_addr
  */
  for (ALL_LIST_ELEMENTS(qpim_upstream_list, up_node, up_nextnode, up)) {

    if (PIM_DEBUG_PIM_TRACE) {
      char neigh_str[100];
      char rpf_addr_str[100];
      pim_inet4_dump("<neigh?>", neigh_addr, neigh_str, sizeof(neigh_str));
      pim_addr_dump("<rpf?>", &up->rpf.rpf_addr, rpf_addr_str, sizeof(rpf_addr_str));
      zlog_debug("%s: matching neigh=%s against upstream (S,G)=%s joined=%d rpf_addr=%s",
		 __PRETTY_FUNCTION__,
		 neigh_str, pim_str_sg_dump (&up->sg),
		 up->join_state == PIM_UPSTREAM_JOINED,
		 rpf_addr_str);
    }

    /* consider only (S,G) upstream in Joined state */
    if (up->join_state != PIM_UPSTREAM_JOINED)
      continue;

    /* match RPF'(S,G)=neigh_addr */
    if (up->rpf.rpf_addr.u.prefix4.s_addr != neigh_addr.s_addr)
      continue;

    pim_upstream_join_timer_decrease_to_t_override("RPF'(S,G) GenID change",
						   up, neigh_addr);
  }
}


void pim_upstream_rpf_interface_changed(struct pim_upstream *up,
					struct interface *old_rpf_ifp)
{
  struct listnode  *ifnode;
  struct listnode  *ifnextnode;
  struct interface *ifp;

  /* scan all interfaces */
  for (ALL_LIST_ELEMENTS (vrf_iflist (VRF_DEFAULT), ifnode, ifnextnode, ifp)) {
    struct listnode      *chnode;
    struct listnode      *chnextnode;
    struct pim_ifchannel *ch;
    struct pim_interface *pim_ifp;

    pim_ifp = ifp->info;
    if (!pim_ifp)
      continue;

    /* search all ifchannels */
    for (ALL_LIST_ELEMENTS(pim_ifp->pim_ifchannel_list, chnode, chnextnode, ch)) {
      if (ch->upstream != up)
	continue;

      if (ch->ifassert_state == PIM_IFASSERT_I_AM_LOSER) {
	if (
	    /* RPF_interface(S) was NOT I */
	    (old_rpf_ifp == ch->interface)
	    &&
	    /* RPF_interface(S) stopped being I */
	    (ch->upstream->rpf.source_nexthop.interface != ch->interface)
	    ) {
	  assert_action_a5(ch);
	}
      } /* PIM_IFASSERT_I_AM_LOSER */

      pim_ifchannel_update_assert_tracking_desired(ch);
    }
  }
}

void pim_upstream_update_could_assert(struct pim_upstream *up)
{
  struct listnode      *ifnode;
  struct listnode      *ifnextnode;
  struct listnode      *chnode;
  struct listnode      *chnextnode;
  struct interface     *ifp;
  struct pim_interface *pim_ifp;
  struct pim_ifchannel *ch;

  /* scan all interfaces */
  for (ALL_LIST_ELEMENTS (vrf_iflist (VRF_DEFAULT), ifnode, ifnextnode, ifp)) {
    pim_ifp = ifp->info;
    if (!pim_ifp)
      continue;

    /* scan per-interface (S,G) state */
    for (ALL_LIST_ELEMENTS(pim_ifp->pim_ifchannel_list, chnode, chnextnode, ch)) {

      if (ch->upstream != up)
	continue;

      pim_ifchannel_update_could_assert(ch);

    } /* scan iface channel list */
  } /* scan iflist */
}

void pim_upstream_update_my_assert_metric(struct pim_upstream *up)
{
  struct listnode      *ifnode;
  struct listnode      *ifnextnode;
  struct listnode      *chnode;
  struct listnode      *chnextnode;
  struct interface     *ifp;
  struct pim_interface *pim_ifp;
  struct pim_ifchannel *ch;

  /* scan all interfaces */
  for (ALL_LIST_ELEMENTS (vrf_iflist (VRF_DEFAULT), ifnode, ifnextnode, ifp)) {
    pim_ifp = ifp->info;
    if (!pim_ifp)
      continue;

    /* scan per-interface (S,G) state */
    for (ALL_LIST_ELEMENTS(pim_ifp->pim_ifchannel_list, chnode, chnextnode, ch)) {

      if (ch->upstream != up)
	continue;

      pim_ifchannel_update_my_assert_metric(ch);

    } /* scan iface channel list */
  } /* scan iflist */
}

static void pim_upstream_update_assert_tracking_desired(struct pim_upstream *up)
{
  struct listnode      *ifnode;
  struct listnode      *ifnextnode;
  struct listnode      *chnode;
  struct listnode      *chnextnode;
  struct interface     *ifp;
  struct pim_interface *pim_ifp;
  struct pim_ifchannel *ch;

  /* scan all interfaces */
  for (ALL_LIST_ELEMENTS (vrf_iflist (VRF_DEFAULT), ifnode, ifnextnode, ifp)) {
    pim_ifp = ifp->info;
    if (!pim_ifp)
      continue;

    /* scan per-interface (S,G) state */
    for (ALL_LIST_ELEMENTS(pim_ifp->pim_ifchannel_list, chnode, chnextnode, ch)) {

      if (ch->upstream != up)
	continue;

      pim_ifchannel_update_assert_tracking_desired(ch);

    } /* scan iface channel list */
  } /* scan iflist */
}

/*
 * On an RP, the PMBR value must be cleared when the
 * Keepalive Timer expires
 */
static int
pim_upstream_keep_alive_timer (struct thread *t)
{
  struct pim_upstream *up;

  up = THREAD_ARG(t);

  if (I_am_RP (up->sg.grp))
    {
      pim_br_clear_pmbr (&up->sg);
      /*
       * We need to do more here :)
       * But this is the start.
       */
    }

  pim_mroute_update_counters (up->channel_oil);

  if ((up->channel_oil->cc.oldpktcnt >= up->channel_oil->cc.pktcnt) &&
      (up->channel_oil->cc.oldlastused >= up->channel_oil->cc.lastused))
    {
      pim_mroute_del (up->channel_oil);
      THREAD_OFF (up->t_ka_timer);
      THREAD_OFF (up->t_rs_timer);
      THREAD_OFF (up->t_join_timer);
      pim_joinprune_send (up->rpf.source_nexthop.interface, up->rpf.rpf_addr.u.prefix4,
                          &up->sg, 0);
      PIM_UPSTREAM_FLAG_UNSET_SRC_STREAM (up->flags);
      pim_upstream_del (up);
    }
  else
    {
      up->t_ka_timer = NULL;
      pim_upstream_keep_alive_timer_start (up, qpim_keep_alive_time);
    }

  return 1;
}

void
pim_upstream_keep_alive_timer_start (struct pim_upstream *up,
				     uint32_t time)
{
  THREAD_OFF (up->t_ka_timer);
  THREAD_TIMER_ON (master,
		   up->t_ka_timer,
		   pim_upstream_keep_alive_timer,
		   up, time);
}

/*
 * 4.2.1 Last-Hop Switchover to the SPT
 *
 *  In Sparse-Mode PIM, last-hop routers join the shared tree towards the
 *  RP.  Once traffic from sources to joined groups arrives at a last-hop
 *  router, it has the option of switching to receive the traffic on a
 *  shortest path tree (SPT).
 *
 *  The decision for a router to switch to the SPT is controlled as
 *  follows:
 *
 *    void
 *    CheckSwitchToSpt(S,G) {
 *      if ( ( pim_include(*,G) (-) pim_exclude(S,G)
 *             (+) pim_include(S,G) != NULL )
 *           AND SwitchToSptDesired(S,G) ) {
 *             # Note: Restarting the KAT will result in the SPT switch
 *             set KeepaliveTimer(S,G) to Keepalive_Period
 *      }
 *    }
 *
 *  SwitchToSptDesired(S,G) is a policy function that is implementation
 *  defined.  An "infinite threshold" policy can be implemented by making
 *  SwitchToSptDesired(S,G) return false all the time.  A "switch on
 *  first packet" policy can be implemented by making
 *  SwitchToSptDesired(S,G) return true once a single packet has been
 *  received for the source and group.
 */
int
pim_upstream_switch_to_spt_desired (struct prefix_sg *sg)
{
  if (I_am_RP (sg->grp))
    return 1;

  return 0;
}

const char *
pim_upstream_state2str (enum pim_upstream_state join_state)
{
  switch (join_state)
    {
    case PIM_UPSTREAM_NOTJOINED:
      return "NtJnd";
      break;
    case PIM_UPSTREAM_JOINED:
      return "Jnd";
      break;
    case PIM_UPSTREAM_JOIN_PENDING:
      return "JPend";
      break;
    case PIM_UPSTREAM_PRUNE:
      return "Prune";
      break;
    }
  return "Unkwn";
}

static int
pim_upstream_register_stop_timer (struct thread *t)
{
  struct pim_interface *pim_ifp;
  struct pim_upstream *up;
  struct pim_rpf *rpg;
  struct ip ip_hdr;
  up = THREAD_ARG (t);

  THREAD_TIMER_OFF (up->t_rs_timer);
  up->t_rs_timer = NULL;

  if (PIM_DEBUG_TRACE)
    {
      zlog_debug ("%s: (S,G)=%s upstream register stop timer %s",
		  __PRETTY_FUNCTION__, pim_str_sg_dump (&up->sg),
                  pim_upstream_state2str(up->join_state));
    }

  switch (up->join_state)
    {
    case PIM_UPSTREAM_JOIN_PENDING:
      up->join_state = PIM_UPSTREAM_JOINED;
      pim_channel_add_oif (up->channel_oil, pim_regiface, PIM_OIF_FLAG_PROTO_PIM);
      break;
    case PIM_UPSTREAM_JOINED:
      break;
    case PIM_UPSTREAM_PRUNE:
      pim_ifp = up->rpf.source_nexthop.interface->info;
      up->join_state = PIM_UPSTREAM_JOIN_PENDING;
      pim_upstream_start_register_stop_timer (up, 1);

      rpg = RP (up->sg.grp);
      memset (&ip_hdr, 0, sizeof (struct ip));
      ip_hdr.ip_p = PIM_IP_PROTO_PIM;
      ip_hdr.ip_hl = 5;
      ip_hdr.ip_v = 4;
      ip_hdr.ip_src = up->sg.src;
      ip_hdr.ip_dst = up->sg.grp;
      ip_hdr.ip_len = htons (20);
      // checksum is broken
      pim_register_send ((uint8_t *)&ip_hdr, sizeof (struct ip),
			 pim_ifp->primary_address, rpg, 1);
      break;
    default:
      break;
    }

  return 0;
}

void
pim_upstream_start_register_stop_timer (struct pim_upstream *up, int null_register)
{
  uint32_t time;

  if (up->t_rs_timer)
    {
      THREAD_TIMER_OFF (up->t_rs_timer);
      up->t_rs_timer = NULL;
    }

  if (!null_register)
    {
      uint32_t lower = (0.5 * PIM_REGISTER_SUPPRESSION_PERIOD);
      uint32_t upper = (1.5 * PIM_REGISTER_SUPPRESSION_PERIOD);
      time = lower + (random () % (upper - lower + 1)) - PIM_REGISTER_PROBE_PERIOD;
    }
  else
    time = PIM_REGISTER_PROBE_PERIOD;

  if (PIM_DEBUG_TRACE)
    {
      zlog_debug ("%s: (S,G)=%s Starting upstream register stop timer %d",
		  __PRETTY_FUNCTION__, pim_str_sg_dump (&up->sg), time);
    }
  THREAD_TIMER_ON (master, up->t_rs_timer,
		   pim_upstream_register_stop_timer,
		   up, time);
}

/*
 * For a given upstream, determine the inherited_olist
 * and apply it.
 *
 * inherited_olist(S,G,rpt) =
 *           ( joins(*,*,RP(G)) (+) joins(*,G) (-) prunes(S,G,rpt) )
 *      (+) ( pim_include(*,G) (-) pim_exclude(S,G))
 *      (-) ( lost_assert(*,G) (+) lost_assert(S,G,rpt) )
 *
 *  inherited_olist(S,G) =
 *      inherited_olist(S,G,rpt) (+)
 *      joins(S,G) (+) pim_include(S,G) (-) lost_assert(S,G)
 *
 * return 1 if there are any output interfaces
 * return 0 if there are not any output interfaces
 */
int
pim_upstream_inherited_olist (struct pim_upstream *up)
{
  struct pim_interface *pim_ifp;
  struct listnode *ifnextnode;
  struct listnode *chnextnode;
  struct pim_ifchannel *ch;
  struct listnode *chnode;
  struct listnode *ifnode;
  struct interface *ifp;
  int output_intf = 0;

  pim_ifp = up->rpf.source_nexthop.interface->info;
  if (pim_ifp && !up->channel_oil)
    up->channel_oil = pim_channel_oil_add (&up->sg, pim_ifp->mroute_vif_index);

  for (ALL_LIST_ELEMENTS (vrf_iflist (VRF_DEFAULT), ifnode, ifnextnode, ifp))
    {
      pim_ifp = ifp->info;
      if (!pim_ifp)
	continue;

      for (ALL_LIST_ELEMENTS (pim_ifp->pim_ifchannel_list, chnode, chnextnode, ch))
	{
	  if (pim_upstream_evaluate_join_desired_interface (up, ch))
	    {
	      pim_channel_add_oif (up->channel_oil, ifp, PIM_OIF_FLAG_PROTO_PIM);
	      output_intf++;
	    }
	}
    }

  /*
   * If we have output_intf switch state to Join and work like normal
   * If we don't have an output_intf that means we are probably a
   * switch on a stick so turn on forwarding to just accept the
   * incoming packets so we don't bother the other stuff!
   */
  if (output_intf)
    pim_upstream_switch (up, PIM_UPSTREAM_JOINED);
  else
    forward_on (up);

  return output_intf;
}

/*
 * When we have a new neighbor,
 * find upstreams that don't have their rpf_addr
 * set and see if the new neighbor allows
 * the join to be sent
 */
void
pim_upstream_find_new_rpf (void)
{
  struct listnode     *up_node;
  struct listnode     *up_nextnode;
  struct pim_upstream *up;

  /*
    Scan all (S,G) upstreams searching for RPF'(S,G)=neigh_addr
  */
  for (ALL_LIST_ELEMENTS(qpim_upstream_list, up_node, up_nextnode, up))
    {
      if (pim_rpf_addr_is_inaddr_any(&up->rpf))
	{
	  if (PIM_DEBUG_PIM_TRACE)
	    zlog_debug ("Upstream %s without a path to send join, checking",
			pim_str_sg_dump (&up->sg));
	  pim_rpf_update (up, NULL);
	}
    }
}
