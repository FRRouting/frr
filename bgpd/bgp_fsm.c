/* BGP-4 Finite State Machine   
   From RFC1771 [A Border Gateway Protocol 4 (BGP-4)]
   Copyright (C) 1996, 97, 98 Kunihiro Ishiguro

This file is part of GNU Zebra.

GNU Zebra is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2, or (at your option) any
later version.

GNU Zebra is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Zebra; see the file COPYING.  If not, write to the Free
Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.  */

#include <zebra.h>

#include "linklist.h"
#include "prefix.h"
#include "vty.h"
#include "sockunion.h"
#include "thread.h"
#include "log.h"
#include "stream.h"
#include "memory.h"
#include "plist.h"
#include "workqueue.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_network.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_dump.h"
#include "bgpd/bgp_open.h"
#include "bgpd/bgp_advertise.h"
#ifdef HAVE_SNMP
#include "bgpd/bgp_snmp.h"
#endif /* HAVE_SNMP */

/* BGP FSM (finite state machine) has three types of functions.  Type
   one is thread functions.  Type two is event functions.  Type three
   is FSM functions.  Timer functions are set by bgp_timer_set
   function. */

/* BGP event function. */
int bgp_event (struct thread *);

/* BGP thread functions. */
static int bgp_start_timer (struct thread *);
static int bgp_connect_timer (struct thread *);
static int bgp_holdtime_timer (struct thread *);
static int bgp_keepalive_timer (struct thread *);

/* BGP FSM functions. */
static int bgp_start (struct peer *);

/* BGP start timer jitter. */
static int
bgp_start_jitter (int time)
{
  return ((rand () % (time + 1)) - (time / 2));
}

static void
peer_xfer_stats (struct peer *peer_dst, struct peer *peer_src)
{
  /* Copy stats over. These are only the pre-established state stats */
  peer_dst->open_in += peer_src->open_in;
  peer_dst->open_out += peer_src->open_out;
  peer_dst->keepalive_in += peer_src->keepalive_in;
  peer_dst->keepalive_out += peer_src->keepalive_out;
  peer_dst->notify_in += peer_src->notify_in;
  peer_dst->notify_out += peer_src->notify_out;
  peer_dst->dynamic_cap_in += peer_src->dynamic_cap_in;
  peer_dst->dynamic_cap_out += peer_src->dynamic_cap_out;
}

static struct peer *
peer_xfer_conn(struct peer *from_peer)
{
  struct peer *peer;
  afi_t afi;
  safi_t safi;
  int fd;
  int status, pstatus;

  assert(from_peer != NULL);

  peer = from_peer->doppelganger;

  if (!peer || !CHECK_FLAG(peer->flags, PEER_FLAG_CONFIG_NODE))
    return from_peer;

  BGP_WRITE_OFF(peer->t_write);
  BGP_READ_OFF(peer->t_read);
  BGP_WRITE_OFF(from_peer->t_write);
  BGP_READ_OFF(from_peer->t_read);

  fd = peer->fd;
  peer->fd = from_peer->fd;
  from_peer->fd = fd;
  stream_reset(peer->ibuf);
  stream_fifo_clean(peer->obuf);
  stream_fifo_clean(from_peer->obuf);

  peer->v_holdtime = from_peer->v_holdtime;
  peer->v_keepalive = from_peer->v_keepalive;
  peer->v_asorig = from_peer->v_asorig;
  peer->routeadv = from_peer->routeadv;
  peer->v_routeadv = from_peer->v_routeadv;
  peer->v_gr_restart = from_peer->v_gr_restart;
  peer->cap = from_peer->cap;
  status = peer->status;
  pstatus = peer->ostatus;
  peer->status = from_peer->status;
  peer->ostatus = from_peer->ostatus;
  from_peer->status = status;
  from_peer->ostatus = pstatus;
  peer->remote_id = from_peer->remote_id;

  for (afi = AFI_IP; afi < AFI_MAX; afi++)
    for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++)
      {
	peer->af_flags[afi][safi] = from_peer->af_flags[afi][safi];
	peer->af_sflags[afi][safi] = from_peer->af_sflags[afi][safi];
	peer->af_cap[afi][safi] = from_peer->af_cap[afi][safi];
	peer->afc_nego[afi][safi] = from_peer->afc_nego[afi][safi];
	peer->afc_adv[afi][safi] = from_peer->afc_adv[afi][safi];
	peer->afc_recv[afi][safi] = from_peer->afc_recv[afi][safi];
      }

  if (bgp_getsockname(peer) < 0)
    {
      zlog_err ("%%bgp_getsockname() failed for %s peer %s fd %d (from_peer fd %d)",
                (CHECK_FLAG (peer->sflags, PEER_STATUS_ACCEPT_PEER) ? "accept" : ""),
                peer->host, peer->fd, from_peer->fd);
      bgp_stop(peer);
      bgp_stop(from_peer);
      return NULL;
    }
  if (from_peer->status > Active)
    {
      if (bgp_getsockname(from_peer) < 0)
        {
          zlog_err ("%%bgp_getsockname() failed for %s from_peer %s fd %d (peer fd %d)",
             (CHECK_FLAG (from_peer->sflags, PEER_STATUS_ACCEPT_PEER) ? "accept" : ""),
             from_peer->host, from_peer->fd, peer->fd);
          bgp_stop(from_peer);
          from_peer = NULL;
        }
    }

  BGP_READ_ON(peer->t_read, bgp_read, peer->fd);
  BGP_WRITE_ON(peer->t_write, bgp_write, peer->fd);

  if (from_peer)
    peer_xfer_stats(peer, from_peer);

  return(peer);
}

/* Check if suppress start/restart of sessions to peer. */
#define BGP_PEER_START_SUPPRESSED(P) \
  (CHECK_FLAG ((P)->flags, PEER_FLAG_SHUTDOWN) \
   || CHECK_FLAG ((P)->sflags, PEER_STATUS_PREFIX_OVERFLOW))

/* Hook function called after bgp event is occered.  And vty's
   neighbor command invoke this function after making neighbor
   structure. */
void
bgp_timer_set (struct peer *peer)
{
  int jitter = 0;

  switch (peer->status)
    {
    case Idle:
      /* First entry point of peer's finite state machine.  In Idle
	 status start timer is on unless peer is shutdown or peer is
	 inactive.  All other timer must be turned off */
      if (BGP_PEER_START_SUPPRESSED (peer) || ! peer_active (peer))
	{
	  BGP_TIMER_OFF (peer->t_start);
	}
      else
	{
	  jitter = bgp_start_jitter (peer->v_start);
	  BGP_TIMER_ON (peer->t_start, bgp_start_timer,
			peer->v_start + jitter);
	}
      BGP_TIMER_OFF (peer->t_connect);
      BGP_TIMER_OFF (peer->t_holdtime);
      BGP_TIMER_OFF (peer->t_keepalive);
      BGP_TIMER_OFF (peer->t_asorig);
      BGP_TIMER_OFF (peer->t_routeadv);
      break;

    case Connect:
      /* After start timer is expired, the peer moves to Connnect
         status.  Make sure start timer is off and connect timer is
         on. */
      BGP_TIMER_OFF (peer->t_start);
      BGP_TIMER_ON (peer->t_connect, bgp_connect_timer, peer->v_connect);
      BGP_TIMER_OFF (peer->t_holdtime);
      BGP_TIMER_OFF (peer->t_keepalive);
      BGP_TIMER_OFF (peer->t_asorig);
      BGP_TIMER_OFF (peer->t_routeadv);
      break;

    case Active:
      /* Active is waiting connection from remote peer.  And if
         connect timer is expired, change status to Connect. */
      BGP_TIMER_OFF (peer->t_start);
      /* If peer is passive mode, do not set connect timer. */
      if (CHECK_FLAG (peer->flags, PEER_FLAG_PASSIVE)
	  || CHECK_FLAG (peer->sflags, PEER_STATUS_NSF_WAIT))
	{
	  BGP_TIMER_OFF (peer->t_connect);
	}
      else
	{
	  BGP_TIMER_ON (peer->t_connect, bgp_connect_timer, peer->v_connect);
	}
      BGP_TIMER_OFF (peer->t_holdtime);
      BGP_TIMER_OFF (peer->t_keepalive);
      BGP_TIMER_OFF (peer->t_asorig);
      BGP_TIMER_OFF (peer->t_routeadv);
      break;

    case OpenSent:
      /* OpenSent status. */
      BGP_TIMER_OFF (peer->t_start);
      BGP_TIMER_OFF (peer->t_connect);
      if (peer->v_holdtime != 0)
	{
	  BGP_TIMER_ON (peer->t_holdtime, bgp_holdtime_timer, 
			peer->v_holdtime);
	}
      else
	{
	  BGP_TIMER_OFF (peer->t_holdtime);
	}
      BGP_TIMER_OFF (peer->t_keepalive);
      BGP_TIMER_OFF (peer->t_asorig);
      BGP_TIMER_OFF (peer->t_routeadv);
      break;

    case OpenConfirm:
      /* OpenConfirm status. */
      BGP_TIMER_OFF (peer->t_start);
      BGP_TIMER_OFF (peer->t_connect);

      /* If the negotiated Hold Time value is zero, then the Hold Time
         timer and KeepAlive timers are not started. */
      if (peer->v_holdtime == 0)
	{
	  BGP_TIMER_OFF (peer->t_holdtime);
	  BGP_TIMER_OFF (peer->t_keepalive);
	}
      else
	{
	  BGP_TIMER_ON (peer->t_holdtime, bgp_holdtime_timer,
			peer->v_holdtime);
	  BGP_TIMER_ON (peer->t_keepalive, bgp_keepalive_timer, 
			peer->v_keepalive);
	}
      BGP_TIMER_OFF (peer->t_asorig);
      BGP_TIMER_OFF (peer->t_routeadv);
      break;

    case Established:
      /* In Established status start and connect timer is turned
         off. */
      BGP_TIMER_OFF (peer->t_start);
      BGP_TIMER_OFF (peer->t_connect);

      /* Same as OpenConfirm, if holdtime is zero then both holdtime
         and keepalive must be turned off. */
      if (peer->v_holdtime == 0)
	{
	  BGP_TIMER_OFF (peer->t_holdtime);
	  BGP_TIMER_OFF (peer->t_keepalive);
	}
      else
	{
	  BGP_TIMER_ON (peer->t_holdtime, bgp_holdtime_timer,
			peer->v_holdtime);
	  BGP_TIMER_ON (peer->t_keepalive, bgp_keepalive_timer,
			peer->v_keepalive);
	}
      BGP_TIMER_OFF (peer->t_asorig);
      break;
    case Deleted:
      BGP_TIMER_OFF (peer->t_gr_restart);
      BGP_TIMER_OFF (peer->t_gr_stale);
      BGP_TIMER_OFF (peer->t_pmax_restart);
    case Clearing:
      BGP_TIMER_OFF (peer->t_start);
      BGP_TIMER_OFF (peer->t_connect);
      BGP_TIMER_OFF (peer->t_holdtime);
      BGP_TIMER_OFF (peer->t_keepalive);
      BGP_TIMER_OFF (peer->t_asorig);
      BGP_TIMER_OFF (peer->t_routeadv);
      break;
    }
}

/* BGP start timer.  This function set BGP_Start event to thread value
   and process event. */
static int
bgp_start_timer (struct thread *thread)
{
  struct peer *peer;

  peer = THREAD_ARG (thread);
  peer->t_start = NULL;

  if (BGP_DEBUG (fsm, FSM))
    zlog (peer->log, LOG_DEBUG,
	  "%s [FSM] Timer (start timer expire).", peer->host);

  THREAD_VAL (thread) = BGP_Start;
  bgp_event (thread);  /* bgp_event unlocks peer */

  return 0;
}

/* BGP connect retry timer. */
static int
bgp_connect_timer (struct thread *thread)
{
  struct peer *peer;
  int ret;

  peer = THREAD_ARG (thread);
  peer->t_connect = NULL;

  if (BGP_DEBUG (fsm, FSM))
    zlog (peer->log, LOG_DEBUG, "%s [FSM] Timer (connect timer expire)",
	  peer->host);

  if (CHECK_FLAG(peer->sflags, PEER_STATUS_ACCEPT_PEER))
    {
      bgp_stop(peer);
      ret = -1;
    }
  else
    {
      THREAD_VAL (thread) = ConnectRetry_timer_expired;
      bgp_event (thread); /* bgp_event unlocks peer */
      ret = 0;
    }

  return ret;
}

/* BGP holdtime timer. */
static int
bgp_holdtime_timer (struct thread *thread)
{
  struct peer *peer;

  peer = THREAD_ARG (thread);
  peer->t_holdtime = NULL;

  if (BGP_DEBUG (fsm, FSM))
    zlog (peer->log, LOG_DEBUG,
	  "%s [FSM] Timer (holdtime timer expire)",
	  peer->host);

  THREAD_VAL (thread) = Hold_Timer_expired;
  bgp_event (thread); /* bgp_event unlocks peer */

  return 0;
}

/* BGP keepalive fire ! */
static int
bgp_keepalive_timer (struct thread *thread)
{
  struct peer *peer;

  peer = THREAD_ARG (thread);
  peer->t_keepalive = NULL;

  if (BGP_DEBUG (fsm, FSM))
    zlog (peer->log, LOG_DEBUG,
	  "%s [FSM] Timer (keepalive timer expire)",
	  peer->host);

  THREAD_VAL (thread) = KeepAlive_timer_expired;
  bgp_event (thread); /* bgp_event unlocks peer */

  return 0;
}

static int
bgp_routeq_empty (struct peer *peer)
{
  afi_t afi;
  safi_t safi;

  for (afi = AFI_IP; afi < AFI_MAX; afi++)
    for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++)
      {
        if (!FIFO_EMPTY(&peer->sync[afi][safi]->withdraw) ||
            !FIFO_EMPTY(&peer->sync[afi][safi]->update))
          return 0;
      }
  return 1;
}

static int
bgp_routeadv_timer (struct thread *thread)
{
  struct peer *peer;

  peer = THREAD_ARG (thread);
  peer->t_routeadv = NULL;

  if (BGP_DEBUG (fsm, FSM))
    zlog (peer->log, LOG_DEBUG,
	  "%s [FSM] Timer (routeadv timer expire)",
	  peer->host);

  peer->synctime = bgp_clock ();

  BGP_WRITE_ON (peer->t_write, bgp_write, peer->fd);

  /*
   * If there is no UPDATE to send, don't start the timer. We will start
   * it when the queues go non-empty.
   */
  if (bgp_routeq_empty(peer))
    return 0;

  BGP_TIMER_ON (peer->t_routeadv, bgp_routeadv_timer, peer->v_routeadv);

  return 0;
}

/* BGP Peer Down Cause */
const char *peer_down_str[] =
{
  "",
  "Router ID changed",
  "Remote AS changed",
  "Local AS change",
  "Cluster ID changed",
  "Confederation identifier changed",
  "Confederation peer changed",
  "RR client config change",
  "RS client config change",
  "Update source change",
  "Address family activated",
  "Admin. shutdown",
  "User reset",
  "BGP Notification received",
  "BGP Notification send",
  "Peer closed the session",
  "Neighbor deleted",
  "Peer-group add member",
  "Peer-group delete member",
  "Capability changed",
  "Passive config change",
  "Multihop config change",
  "NSF peer closed the session"
};

static int
bgp_graceful_restart_timer_expire (struct thread *thread)
{
  struct peer *peer;
  afi_t afi;
  safi_t safi;

  peer = THREAD_ARG (thread);
  peer->t_gr_restart = NULL;

  /* NSF delete stale route */
  for (afi = AFI_IP ; afi < AFI_MAX ; afi++)
    for (safi = SAFI_UNICAST ; safi < SAFI_RESERVED_3 ; safi++)
      if (peer->nsf[afi][safi])
	bgp_clear_stale_route (peer, afi, safi);

  UNSET_FLAG (peer->sflags, PEER_STATUS_NSF_WAIT);
  BGP_TIMER_OFF (peer->t_gr_stale);

  if (BGP_DEBUG (events, EVENTS))
    {
      zlog_debug ("%s graceful restart timer expired", peer->host);
      zlog_debug ("%s graceful restart stalepath timer stopped", peer->host);
    }

  bgp_timer_set (peer);

  return 0;
}

static int
bgp_graceful_stale_timer_expire (struct thread *thread)
{
  struct peer *peer;
  afi_t afi;
  safi_t safi;

  peer = THREAD_ARG (thread);
  peer->t_gr_stale = NULL;

  if (BGP_DEBUG (events, EVENTS))
    zlog_debug ("%s graceful restart stalepath timer expired", peer->host);

  /* NSF delete stale route */
  for (afi = AFI_IP ; afi < AFI_MAX ; afi++)
    for (safi = SAFI_UNICAST ; safi < SAFI_RESERVED_3 ; safi++)
      if (peer->nsf[afi][safi])
	bgp_clear_stale_route (peer, afi, safi);

  return 0;
}

static int
bgp_update_delay_applicable (struct bgp *bgp)
{
  /* update_delay_over flag should be reset (set to 0) for any new
     applicability of the update-delay during BGP process lifetime.
     And it should be set after an occurence of the update-delay is over)*/
  if (!bgp->update_delay_over)
    return 1;

  return 0;
}

int
bgp_update_delay_active (struct bgp *bgp)
{
  if (bgp->t_update_delay)
    return 1;

  return 0;
}

int
bgp_update_delay_configured (struct bgp *bgp)
{
  if (bgp->v_update_delay)
    return 1;

  return 0;
}

/* Do the post-processing needed when bgp comes out of the read-only mode
   on ending the update delay. */
void
bgp_update_delay_end (struct bgp *bgp)
{
  struct listnode *node, *nnode;
  struct peer *peer;

  THREAD_TIMER_OFF (bgp->t_update_delay);
  THREAD_TIMER_OFF (bgp->t_establish_wait);

  /* Reset update-delay related state */
  bgp->update_delay_over = 1;
  bgp->established = 0;
  bgp->restarted_peers = 0;
  bgp->implicit_eors = 0;
  bgp->explicit_eors = 0;

  quagga_timestamp(3, bgp->update_delay_end_time,
                   sizeof(bgp->update_delay_end_time));

  /*
   * Add an end-of-initial-update marker to the main process queues so that
   * the route advertisement timer for the peers can be started.
   */
  bgp_add_eoiu_mark(bgp, BGP_TABLE_MAIN);
  bgp_add_eoiu_mark(bgp, BGP_TABLE_RSCLIENT);

  /* Route announcements were postponed for all the peers during read-only mode,
     send those now. */
  for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
    bgp_announce_route_all (peer);

  /* Resume the queue processing. This should trigger the event that would take
     care of processing any work that was queued during the read-only mode. */
  work_queue_unplug(bm->process_main_queue);
  work_queue_unplug(bm->process_rsclient_queue);
}

/**
 * see bgp_fsm.h
 */
void
bgp_start_routeadv (struct bgp *bgp)
{
  struct listnode *node, *nnode;
  struct peer *peer;

  for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
    {
      if (peer->status != Established)
	continue;
      BGP_TIMER_OFF(peer->t_routeadv);
      BGP_TIMER_ON(peer->t_routeadv, bgp_routeadv_timer, 0);
    }
}

/**
 * see bgp_fsm.h
 */
void
bgp_adjust_routeadv (struct peer *peer)
{
  time_t nowtime = bgp_clock();
  double diff;
  unsigned long remain;

  /*
   * CASE I:
   * If the last update was written more than MRAI back, expire the timer
   * instantly so that we can send the update out sooner.
   *
   *                           <-------  MRAI --------->
   *         |-----------------|-----------------------|
   *         <------------- m ------------>
   *         ^                 ^          ^
   *         |                 |          |
   *         |                 |     current time
   *         |            timer start
   *      last write
   *
   *                     m > MRAI
   */
  diff = difftime(nowtime, peer->last_write);
  if (diff > (double) peer->v_routeadv)
    {
      BGP_TIMER_OFF(peer->t_routeadv);
      BGP_TIMER_ON(peer->t_routeadv, bgp_routeadv_timer, 0);
      if (BGP_DEBUG (update, UPDATE_OUT))
	zlog (peer->log, LOG_DEBUG, "%s: MRAI timer to expire instantly\n",
	      peer->host);
      return;
    }

  /*
   * CASE II:
   * - Find when to expire the MRAI timer.
   *   If MRAI timer is not active, assume we can start it now.
   *
   *                      <-------  MRAI --------->
   *         |------------|-----------------------|
   *         <-------- m ----------><----- r ----->
   *         ^            ^        ^
   *         |            |        |
   *         |            |   current time
   *         |       timer start
   *      last write
   *
   *                     (MRAI - m) < r
   */
  if (peer->t_routeadv)
    remain = thread_timer_remain_second(peer->t_routeadv);
  else
    remain = peer->v_routeadv;
  diff = peer->v_routeadv - diff;
  if (diff <= (double) remain)
    {
      BGP_TIMER_OFF(peer->t_routeadv);
      BGP_TIMER_ON(peer->t_routeadv, bgp_routeadv_timer, diff);
      if (BGP_DEBUG (update, UPDATE_OUT))
	zlog (peer->log, LOG_DEBUG, "%s: MRAI timer to expire in %f secs\n",
	      peer->host, diff);
    }
}

/* The update delay timer expiry callback. */
static int
bgp_update_delay_timer (struct thread *thread)
{
  struct bgp *bgp;

  zlog_info ("Update delay ended - timer expired.");

  bgp = THREAD_ARG (thread);
  THREAD_TIMER_OFF (bgp->t_update_delay);
  bgp_update_delay_end(bgp);

  return 0;
}

/* The establish wait timer expiry callback. */
static int
bgp_establish_wait_timer (struct thread *thread)
{
  struct bgp *bgp;

  zlog_info ("Establish wait - timer expired.");

  bgp = THREAD_ARG (thread);
  THREAD_TIMER_OFF (bgp->t_establish_wait);
  bgp_check_update_delay(bgp);

  return 0;
}

/* Steps to begin the update delay:
     - initialize queues if needed
     - stop the queue processing
     - start the timer */
static void
bgp_update_delay_begin (struct bgp *bgp)
{
  struct listnode *node, *nnode;
  struct peer *peer;

  if ((bm->process_main_queue == NULL) ||
      (bm->process_rsclient_queue == NULL))
    bgp_process_queue_init();

  /* Stop the processing of queued work. Enqueue shall continue */
  work_queue_plug(bm->process_main_queue);
  work_queue_plug(bm->process_rsclient_queue);

  for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
    peer->update_delay_over = 0;

  /* Start the update-delay timer */
  THREAD_TIMER_ON (master, bgp->t_update_delay, bgp_update_delay_timer,
                   bgp, bgp->v_update_delay);

  if (bgp->v_establish_wait != bgp->v_update_delay)
    THREAD_TIMER_ON (master, bgp->t_establish_wait, bgp_establish_wait_timer,
                     bgp, bgp->v_establish_wait);

  quagga_timestamp(3, bgp->update_delay_begin_time,
                   sizeof(bgp->update_delay_begin_time));
}

static void
bgp_update_delay_process_status_change(struct peer *peer)
{
  if (peer->status == Established)
    {
      if (!peer->bgp->established++)
        {
          bgp_update_delay_begin(peer->bgp);
          zlog_info ("Begin read-only mode - update-delay timer %d seconds",
                     peer->bgp->v_update_delay);
        }
      if (CHECK_FLAG (peer->cap, PEER_CAP_RESTART_BIT_RCV))
        bgp_update_restarted_peers(peer);
    }
  if (peer->ostatus == Established && bgp_update_delay_active(peer->bgp))
    {
      /* Adjust the update-delay state to account for this flap.
         NOTE: Intentionally skipping adjusting implicit_eors or explicit_eors
         counters. Extra sanity check in bgp_check_update_delay() should
         be enough to take care of any additive discrepancy in bgp eor
         counters */
      peer->bgp->established--;
      peer->update_delay_over = 0;
    }
}

/* Called after event occured, this function change status and reset
   read/write and timer thread. */
void
bgp_fsm_change_status (struct peer *peer, int status)
{

  bgp_dump_state (peer, peer->status, status);

  /* Transition into Clearing or Deleted must /always/ clear all routes.. 
   * (and must do so before actually changing into Deleted..
   */
  if (status >= Clearing)
    bgp_clear_route_all (peer);
  
  /* Preserve old status and change into new status. */
  peer->ostatus = peer->status;
  peer->status = status;

  if (status == Established)
    UNSET_FLAG(peer->sflags, PEER_STATUS_ACCEPT_PEER);

  /* If update-delay processing is applicable, do the necessary. */
  if (bgp_update_delay_configured(peer->bgp) &&
      bgp_update_delay_applicable(peer->bgp))
    bgp_update_delay_process_status_change(peer);

  if (BGP_DEBUG (normal, NORMAL))
    zlog_debug ("%s went from %s to %s",
		peer->host,
		LOOKUP (bgp_status_msg, peer->ostatus),
		LOOKUP (bgp_status_msg, peer->status));
}

/* Flush the event queue and ensure the peer is shut down */
static int
bgp_clearing_completed (struct peer *peer)
{
  int rc = bgp_stop(peer);

  if (rc >= 0)
    BGP_EVENT_FLUSH (peer);

  return rc;
}

/* Administrative BGP peer stop event. */
/* May be called multiple times for the same peer */
int
bgp_stop (struct peer *peer)
{
  afi_t afi;
  safi_t safi;
  char orf_name[BUFSIZ];
  int ret = 0;

  /* Can't do this in Clearing; events are used for state transitions */
  if (peer->status != Clearing)
    {
      /* Delete all existing events of the peer */
      BGP_EVENT_FLUSH (peer);
    }

  /* Increment Dropped count. */
  if (peer->status == Established)
    {
      peer->dropped++;

      /* bgp log-neighbor-changes of neighbor Down */
      if (bgp_flag_check (peer->bgp, BGP_FLAG_LOG_NEIGHBOR_CHANGES))
	zlog_info ("%%ADJCHANGE: neighbor %s Down %s", peer->host,
                   peer_down_str [(int) peer->last_reset]);

      /* graceful restart */
      if (peer->t_gr_stale)
	{
	  BGP_TIMER_OFF (peer->t_gr_stale);
	  if (BGP_DEBUG (events, EVENTS))
	    zlog_debug ("%s graceful restart stalepath timer stopped", peer->host);
	}
      if (CHECK_FLAG (peer->sflags, PEER_STATUS_NSF_WAIT))
	{
	  if (BGP_DEBUG (events, EVENTS))
	    {
	      zlog_debug ("%s graceful restart timer started for %d sec",
			  peer->host, peer->v_gr_restart);
	      zlog_debug ("%s graceful restart stalepath timer started for %d sec",
			  peer->host, peer->bgp->stalepath_time);
	    }
	  BGP_TIMER_ON (peer->t_gr_restart, bgp_graceful_restart_timer_expire,
			peer->v_gr_restart);
	  BGP_TIMER_ON (peer->t_gr_stale, bgp_graceful_stale_timer_expire,
			peer->bgp->stalepath_time);
	}
      else
	{
	  UNSET_FLAG (peer->sflags, PEER_STATUS_NSF_MODE);

	  for (afi = AFI_IP ; afi < AFI_MAX ; afi++)
	    for (safi = SAFI_UNICAST ; safi < SAFI_RESERVED_3 ; safi++)
	      peer->nsf[afi][safi] = 0;
	}

      /* set last reset time */
      peer->resettime = peer->uptime = bgp_clock ();

#ifdef HAVE_SNMP
      bgpTrapBackwardTransition (peer);
#endif /* HAVE_SNMP */

      /* Reset peer synctime */
      peer->synctime = 0;
    }

  /* Stop read and write threads when exists. */
  BGP_READ_OFF (peer->t_read);
  BGP_WRITE_OFF (peer->t_write);

  /* Stop all timers. */
  BGP_TIMER_OFF (peer->t_start);
  BGP_TIMER_OFF (peer->t_connect);
  BGP_TIMER_OFF (peer->t_holdtime);
  BGP_TIMER_OFF (peer->t_keepalive);
  BGP_TIMER_OFF (peer->t_asorig);
  BGP_TIMER_OFF (peer->t_routeadv);

  /* Stream reset. */
  peer->packet_size = 0;

  /* Clear input and output buffer.  */
  if (peer->ibuf)
    stream_reset (peer->ibuf);
  if (peer->work)
    stream_reset (peer->work);
  if (peer->obuf)
    stream_fifo_clean (peer->obuf);

  /* Close of file descriptor. */
  if (peer->fd >= 0)
    {
      close (peer->fd);
      peer->fd = -1;
    }

  for (afi = AFI_IP ; afi < AFI_MAX ; afi++)
    for (safi = SAFI_UNICAST ; safi < SAFI_MAX ; safi++)
      {
        /* Reset all negotiated variables */
        peer->afc_nego[afi][safi] = 0;
        peer->afc_adv[afi][safi] = 0;
        peer->afc_recv[afi][safi] = 0;

	/* peer address family capability flags*/
	peer->af_cap[afi][safi] = 0;

	/* peer address family status flags*/
	peer->af_sflags[afi][safi] = 0;

	/* Received ORF prefix-filter */
	peer->orf_plist[afi][safi] = NULL;

	if ((peer->status == OpenConfirm) || (peer->status == Established))  {
	  /* ORF received prefix-filter pnt */
	  sprintf (orf_name, "%s.%d.%d", peer->host, afi, safi);
	  prefix_bgp_orf_remove_all (orf_name);
	}
      }

  /* Reset keepalive and holdtime */
  if (CHECK_FLAG (peer->config, PEER_CONFIG_TIMER))
    {
      peer->v_keepalive = peer->keepalive;
      peer->v_holdtime = peer->holdtime;
    }
  else
    {
      peer->v_keepalive = peer->bgp->default_keepalive;
      peer->v_holdtime = peer->bgp->default_holdtime;
    }

  peer->update_time = 0;

  /* Until we are sure that there is no problem about prefix count
     this should be commented out.*/
#if 0
  /* Reset prefix count */
  peer->pcount[AFI_IP][SAFI_UNICAST] = 0;
  peer->pcount[AFI_IP][SAFI_MULTICAST] = 0;
  peer->pcount[AFI_IP][SAFI_MPLS_VPN] = 0;
  peer->pcount[AFI_IP6][SAFI_UNICAST] = 0;
  peer->pcount[AFI_IP6][SAFI_MULTICAST] = 0;
#endif /* 0 */

  if (!CHECK_FLAG(peer->flags, PEER_FLAG_CONFIG_NODE) &&
      !(CHECK_FLAG(peer->flags, PEER_FLAG_DELETE)))
    {
      peer_delete(peer);
      ret = -1;
    }

  return ret;
}

/* BGP peer is stoped by the error. */
static int
bgp_stop_with_error (struct peer *peer)
{
  /* Double start timer. */
  peer->v_start *= 2;

  /* Overflow check. */
  if (peer->v_start >= (60 * 2))
    peer->v_start = (60 * 2);

  return(bgp_stop (peer));
}


/* something went wrong, send notify and tear down */
static int
bgp_stop_with_notify (struct peer *peer, u_char code, u_char sub_code)
{
  /* Send notify to remote peer */
  bgp_notify_send (peer, code, sub_code);

  /* Clear start timer value to default. */
  peer->v_start = BGP_INIT_START_TIMER;

  return(bgp_stop(peer));
}


/* TCP connection open.  Next we send open message to remote peer. And
   add read thread for reading open message. */
static int
bgp_connect_success (struct peer *peer)
{
  int ret = 0;

  if (peer->fd < 0)
    {
      zlog_err ("bgp_connect_success peer's fd is negative value %d",
		peer->fd);
      bgp_stop(peer);
      return -1;
    }

  if (bgp_getsockname (peer) < 0)
    {
      zlog_err ("%s: bgp_getsockname(): failed for peer %s", __FUNCTION__,
		peer->host);
      bgp_notify_send(peer, BGP_NOTIFY_FSM_ERR, 0); /* internal error */
      return -1;
    }

  BGP_READ_ON (peer->t_read, bgp_read, peer->fd);

  if (BGP_DEBUG (normal, NORMAL))
    {
      char buf1[SU_ADDRSTRLEN];

      if (! CHECK_FLAG (peer->sflags, PEER_STATUS_ACCEPT_PEER))
	zlog_debug ("%s open active, local address %s", peer->host,
		    sockunion2str (peer->su_local, buf1, SU_ADDRSTRLEN));
      else
	zlog_debug ("%s passive open", peer->host);
    }

  bgp_open_send (peer);

  return 0;
}

/* TCP connect fail */
static int
bgp_connect_fail (struct peer *peer)
{
  return (bgp_stop (peer));
}

/* This function is the first starting point of all BGP connection. It
   try to connect to remote peer with non-blocking IO. */
int
bgp_start (struct peer *peer)
{
  int status;

  if (BGP_PEER_START_SUPPRESSED (peer))
    {
      if (BGP_DEBUG (fsm, FSM))
        plog_err (peer->log, "%s [FSM] Trying to start suppressed peer"
                  " - this is never supposed to happen!", peer->host);
      return -1;
    }

  /* Scrub some information that might be left over from a previous,
   * session
   */
  /* Connection information. */
  if (peer->su_local)
    {
      sockunion_free (peer->su_local);
      peer->su_local = NULL;
    }

  if (peer->su_remote)
    {
      sockunion_free (peer->su_remote);
      peer->su_remote = NULL;
    }

  /* Clear remote router-id. */
  peer->remote_id.s_addr = 0;

  /* Clear peer capability flag. */
  peer->cap = 0;
    
  /* If the peer is passive mode, force to move to Active mode. */
  if (CHECK_FLAG (peer->flags, PEER_FLAG_PASSIVE))
    {
      BGP_EVENT_ADD (peer, TCP_connection_open_failed);
      return 0;
    }

  status = bgp_connect (peer);

  switch (status)
    {
    case connect_error:
      if (BGP_DEBUG (fsm, FSM))
	plog_debug (peer->log, "%s [FSM] Connect error", peer->host);
      BGP_EVENT_ADD (peer, TCP_connection_open_failed);
      break;
    case connect_success:
      if (BGP_DEBUG (fsm, FSM))
	plog_debug (peer->log, "%s [FSM] Connect immediately success",
		   peer->host);
      BGP_EVENT_ADD (peer, TCP_connection_open);
      break;
    case connect_in_progress:
      /* To check nonblocking connect, we wait until socket is
         readable or writable. */
      if (BGP_DEBUG (fsm, FSM))
	plog_debug (peer->log, "%s [FSM] Non blocking connect waiting result",
		   peer->host);
      if (peer->fd < 0)
	{
	  zlog_err ("bgp_start peer's fd is negative value %d",
		    peer->fd);
	  return -1;
	}
      BGP_READ_ON (peer->t_read, bgp_read, peer->fd);
      BGP_WRITE_ON (peer->t_write, bgp_write, peer->fd);
      break;
    }
  return 0;
}

/* Connect retry timer is expired when the peer status is Connect. */
static int
bgp_reconnect (struct peer *peer)
{
  int ret = 0;

  if (bgp_stop (peer) > 0)
    bgp_start (peer);
  else
    ret = -1;

  return ret;
}

static int
bgp_fsm_open (struct peer *peer)
{
  /* Send keepalive and make keepalive timer */
  bgp_keepalive_send (peer);

  /* Reset holdtimer value. */
  BGP_TIMER_OFF (peer->t_holdtime);

  return 0;
}

/* Keepalive send to peer. */
static int
bgp_fsm_keepalive_expire (struct peer *peer)
{
  /*
   * If there are UPDATE messages to send, no need to send keepalive. The
   * peer will note our progress through the UPDATEs.
   */
  if (!bgp_routeq_empty(peer))
    return 0;

  bgp_keepalive_send (peer);
  return 0;
}

/* FSM error, unexpected event.  This is error of BGP connection. So cut the
   peer and change to Idle status. */
static int
bgp_fsm_event_error (struct peer *peer)
{
  plog_err (peer->log, "%s [FSM] unexpected packet received in state %s",
	    peer->host, LOOKUP (bgp_status_msg, peer->status));

  return bgp_stop_with_notify (peer, BGP_NOTIFY_FSM_ERR, 0);
}

/* Hold timer expire.  This is error of BGP connection. So cut the
   peer and change to Idle status. */
static int
bgp_fsm_holdtime_expire (struct peer *peer)
{
  if (BGP_DEBUG (fsm, FSM))
    plog_debug (peer->log, "%s [FSM] Hold timer expire", peer->host);

  return bgp_stop_with_notify (peer, BGP_NOTIFY_HOLD_ERR, 0);
}

/* Status goes to Established.  Send keepalive packet then make first
   update information. */
static int
bgp_establish (struct peer *peer)
{
  struct bgp_notify *notify;
  afi_t afi;
  safi_t safi;
  int nsf_af_count = 0;
  int ret = 0;
  struct peer *other;

  other = peer->doppelganger;
  peer = peer_xfer_conn(peer);
  if (!peer)
    {
      zlog_err ("%%Neighbor failed in xfer_conn");
      return -1;
    }

  if (other == peer)
    ret = 1; /* bgp_establish specific code when xfer_conn happens. */

  /* Reset capability open status flag. */
  if (! CHECK_FLAG (peer->sflags, PEER_STATUS_CAPABILITY_OPEN))
    SET_FLAG (peer->sflags, PEER_STATUS_CAPABILITY_OPEN);

  /* Clear last notification data. */
  notify = &peer->notify;
  if (notify->data)
    XFREE (MTYPE_TMP, notify->data);
  memset (notify, 0, sizeof (struct bgp_notify));

  /* Clear start timer value to default. */
  peer->v_start = BGP_INIT_START_TIMER;

  /* Increment established count. */
  peer->established++;
  bgp_fsm_change_status (peer, Established);

  /* bgp log-neighbor-changes of neighbor Up */
  if (bgp_flag_check (peer->bgp, BGP_FLAG_LOG_NEIGHBOR_CHANGES))
    zlog_info ("%%ADJCHANGE: neighbor %s Up", peer->host);

  /* graceful restart */
  UNSET_FLAG (peer->sflags, PEER_STATUS_NSF_WAIT);
  for (afi = AFI_IP ; afi < AFI_MAX ; afi++)
    for (safi = SAFI_UNICAST ; safi < SAFI_RESERVED_3 ; safi++)
      {
	if (peer->afc_nego[afi][safi]
	    && CHECK_FLAG (peer->cap, PEER_CAP_RESTART_ADV)
	    && CHECK_FLAG (peer->af_cap[afi][safi], PEER_CAP_RESTART_AF_RCV))
	  {
	    if (peer->nsf[afi][safi]
		&& ! CHECK_FLAG (peer->af_cap[afi][safi], PEER_CAP_RESTART_AF_PRESERVE_RCV))
	      bgp_clear_stale_route (peer, afi, safi);

	    peer->nsf[afi][safi] = 1;
	    nsf_af_count++;
	  }
	else
	  {
	    if (peer->nsf[afi][safi])
	      bgp_clear_stale_route (peer, afi, safi);
	    peer->nsf[afi][safi] = 0;
	  }
      }

  if (nsf_af_count)
    SET_FLAG (peer->sflags, PEER_STATUS_NSF_MODE);
  else
    {
      UNSET_FLAG (peer->sflags, PEER_STATUS_NSF_MODE);
      if (peer->t_gr_stale)
	{
	  BGP_TIMER_OFF (peer->t_gr_stale);
	  if (BGP_DEBUG (events, EVENTS))
	    zlog_debug ("%s graceful restart stalepath timer stopped", peer->host);
	}
    }

  if (peer->t_gr_restart)
    {
      BGP_TIMER_OFF (peer->t_gr_restart);
      if (BGP_DEBUG (events, EVENTS))
	zlog_debug ("%s graceful restart timer stopped", peer->host);
    }

#ifdef HAVE_SNMP
  bgpTrapEstablished (peer);
#endif /* HAVE_SNMP */

  /* Reset uptime, send keepalive, send current table. */
  peer->uptime = bgp_clock ();

  /* Send route-refresh when ORF is enabled */
  for (afi = AFI_IP ; afi < AFI_MAX ; afi++)
    for (safi = SAFI_UNICAST ; safi < SAFI_MAX ; safi++)
      if (CHECK_FLAG (peer->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_SM_ADV))
	{
	  if (CHECK_FLAG (peer->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_RM_RCV))
	    bgp_route_refresh_send (peer, afi, safi, ORF_TYPE_PREFIX,
				    REFRESH_IMMEDIATE, 0);
	  else if (CHECK_FLAG (peer->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_RM_OLD_RCV))
	    bgp_route_refresh_send (peer, afi, safi, ORF_TYPE_PREFIX_OLD,
				    REFRESH_IMMEDIATE, 0);
	}

  /* First update is deferred until ORF or ROUTE-REFRESH is received */
  for (afi = AFI_IP ; afi < AFI_MAX ; afi++)
    for (safi = SAFI_UNICAST ; safi < SAFI_MAX ; safi++)
      if (CHECK_FLAG (peer->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_RM_ADV))
	if (CHECK_FLAG (peer->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_SM_RCV)
	    || CHECK_FLAG (peer->af_cap[afi][safi], PEER_CAP_ORF_PREFIX_SM_OLD_RCV))
	  SET_FLAG (peer->af_sflags[afi][safi], PEER_STATUS_ORF_WAIT_REFRESH);

  bgp_announce_route_all (peer);

  /* Start the route advertisement timer to send updates to the peer - if BGP
   * is not in read-only mode. If it is, the timer will be started at the end
   * of read-only mode.
   */
  if (!bgp_update_delay_active(peer->bgp))
    BGP_TIMER_ON (peer->t_routeadv, bgp_routeadv_timer, 0);

  if (peer->doppelganger && (peer->doppelganger->status != Deleted))
    {
      if (BGP_DEBUG (events, EVENTS))
	zlog_debug("[Event] Deleting stub connection for peer %s", peer->host);

      if (peer->doppelganger->status > Active)
	bgp_notify_send (peer->doppelganger, BGP_NOTIFY_CEASE,
			 BGP_NOTIFY_CEASE_COLLISION_RESOLUTION);
      else
	peer_delete(peer->doppelganger);
    }

  return ret;
}

/* Keepalive packet is received. */
static int
bgp_fsm_keepalive (struct peer *peer)
{
  bgp_update_implicit_eors(peer);

  /* peer count update */
  peer->keepalive_in++;

  BGP_TIMER_OFF (peer->t_holdtime);
  return 0;
}

/* Update packet is received. */
static int
bgp_fsm_update (struct peer *peer)
{
  BGP_TIMER_OFF (peer->t_holdtime);
  return 0;
}

/* This is empty event. */
static int
bgp_ignore (struct peer *peer)
{
  if (BGP_DEBUG (fsm, FSM))
    zlog (peer->log, LOG_DEBUG, "%s [FSM] bgp_ignore called", peer->host);
  return 0;
}

/* Finite State Machine structure */
static const struct {
  int (*func) (struct peer *);
  int next_state;
} FSM [BGP_STATUS_MAX - 1][BGP_EVENTS_MAX - 1] = 
{
  {
    /* Idle state: In Idle state, all events other than BGP_Start is
       ignored.  With BGP_Start event, finite state machine calls
       bgp_start(). */
    {bgp_start,  Connect},	/* BGP_Start                    */
    {bgp_stop,   Idle},		/* BGP_Stop                     */
    {bgp_stop,   Idle},		/* TCP_connection_open          */
    {bgp_stop,   Idle},		/* TCP_connection_closed        */
    {bgp_ignore, Idle},		/* TCP_connection_open_failed   */
    {bgp_stop,   Idle},		/* TCP_fatal_error              */
    {bgp_ignore, Idle},		/* ConnectRetry_timer_expired   */
    {bgp_ignore, Idle},		/* Hold_Timer_expired           */
    {bgp_ignore, Idle},		/* KeepAlive_timer_expired      */
    {bgp_ignore, Idle},		/* Receive_OPEN_message         */
    {bgp_ignore, Idle},		/* Receive_KEEPALIVE_message    */
    {bgp_ignore, Idle},		/* Receive_UPDATE_message       */
    {bgp_ignore, Idle},		/* Receive_NOTIFICATION_message */
    {bgp_ignore, Idle},         /* Clearing_Completed           */
  },
  {
    /* Connect */
    {bgp_ignore,  Connect},	/* BGP_Start                    */
    {bgp_stop,    Idle},	/* BGP_Stop                     */
    {bgp_connect_success, OpenSent}, /* TCP_connection_open          */
    {bgp_stop, Idle},		/* TCP_connection_closed        */
    {bgp_connect_fail, Active}, /* TCP_connection_open_failed   */
    {bgp_connect_fail, Idle},	/* TCP_fatal_error              */
    {bgp_reconnect, Connect},	/* ConnectRetry_timer_expired   */
    {bgp_ignore,  Idle},	/* Hold_Timer_expired           */
    {bgp_ignore,  Idle},	/* KeepAlive_timer_expired      */
    {bgp_ignore,  Idle},	/* Receive_OPEN_message         */
    {bgp_ignore,  Idle},	/* Receive_KEEPALIVE_message    */
    {bgp_ignore,  Idle},	/* Receive_UPDATE_message       */
    {bgp_stop,    Idle},	/* Receive_NOTIFICATION_message */
    {bgp_ignore,  Idle},         /* Clearing_Completed           */
  },
  {
    /* Active, */
    {bgp_ignore,  Active},	/* BGP_Start                    */
    {bgp_stop,    Idle},	/* BGP_Stop                     */
    {bgp_connect_success, OpenSent}, /* TCP_connection_open          */
    {bgp_stop,    Idle},	/* TCP_connection_closed        */
    {bgp_ignore,  Active},	/* TCP_connection_open_failed   */
    {bgp_ignore,  Idle},	/* TCP_fatal_error              */
    {bgp_start,   Connect},	/* ConnectRetry_timer_expired   */
    {bgp_ignore,  Idle},	/* Hold_Timer_expired           */
    {bgp_ignore,  Idle},	/* KeepAlive_timer_expired      */
    {bgp_ignore,  Idle},	/* Receive_OPEN_message         */
    {bgp_ignore,  Idle},	/* Receive_KEEPALIVE_message    */
    {bgp_ignore,  Idle},	/* Receive_UPDATE_message       */
    {bgp_stop_with_error, Idle}, /* Receive_NOTIFICATION_message */
    {bgp_ignore, Idle},         /* Clearing_Completed           */
  },
  {
    /* OpenSent, */
    {bgp_ignore,  OpenSent},	/* BGP_Start                    */
    {bgp_stop,    Idle},	/* BGP_Stop                     */
    {bgp_stop,    Active},	/* TCP_connection_open          */
    {bgp_stop,    Active},	/* TCP_connection_closed        */
    {bgp_stop,    Active},	/* TCP_connection_open_failed   */
    {bgp_stop,    Active},	/* TCP_fatal_error              */
    {bgp_ignore,  Idle},	/* ConnectRetry_timer_expired   */
    {bgp_fsm_holdtime_expire, Idle},	/* Hold_Timer_expired           */
    {bgp_ignore,  Idle},	/* KeepAlive_timer_expired      */
    {bgp_fsm_open,    OpenConfirm},	/* Receive_OPEN_message         */
    {bgp_fsm_event_error, Idle}, /* Receive_KEEPALIVE_message    */
    {bgp_fsm_event_error, Idle}, /* Receive_UPDATE_message       */
    {bgp_stop_with_error, Idle}, /* Receive_NOTIFICATION_message */
    {bgp_ignore, Idle},         /* Clearing_Completed           */
  },
  {
    /* OpenConfirm, */
    {bgp_ignore,  OpenConfirm},	/* BGP_Start                    */
    {bgp_stop,    Idle},	/* BGP_Stop                     */
    {bgp_stop,    Idle},	/* TCP_connection_open          */
    {bgp_stop,    Idle},	/* TCP_connection_closed        */
    {bgp_stop,    Idle},	/* TCP_connection_open_failed   */
    {bgp_stop,    Idle},	/* TCP_fatal_error              */
    {bgp_ignore,  Idle},	/* ConnectRetry_timer_expired   */
    {bgp_fsm_holdtime_expire, Idle},	/* Hold_Timer_expired           */
    {bgp_ignore,  OpenConfirm},	/* KeepAlive_timer_expired      */
    {bgp_ignore,  Idle},	/* Receive_OPEN_message         */
    {bgp_establish, Established}, /* Receive_KEEPALIVE_message    */
    {bgp_ignore,  Idle},	/* Receive_UPDATE_message       */
    {bgp_stop_with_error, Idle}, /* Receive_NOTIFICATION_message */
    {bgp_ignore, Idle},         /* Clearing_Completed           */
  },
  {
    /* Established, */
    {bgp_ignore,               Established}, /* BGP_Start                    */
    {bgp_stop,                    Clearing}, /* BGP_Stop                     */
    {bgp_stop,                    Clearing}, /* TCP_connection_open          */
    {bgp_stop,                    Clearing}, /* TCP_connection_closed        */
    {bgp_stop,                 Clearing},	/* TCP_connection_open_failed   */
    {bgp_stop,                    Clearing}, /* TCP_fatal_error              */
    {bgp_stop,                 Clearing},	/* ConnectRetry_timer_expired   */
    {bgp_fsm_holdtime_expire,     Clearing}, /* Hold_Timer_expired           */
    {bgp_fsm_keepalive_expire, Established}, /* KeepAlive_timer_expired      */
    {bgp_stop,                    Clearing}, /* Receive_OPEN_message         */
    {bgp_fsm_keepalive,        Established}, /* Receive_KEEPALIVE_message    */
    {bgp_fsm_update,           Established}, /* Receive_UPDATE_message       */
    {bgp_stop_with_error,         Clearing}, /* Receive_NOTIFICATION_message */
    {bgp_ignore,                      Idle}, /* Clearing_Completed           */
  },
  {
    /* Clearing, */
    {bgp_ignore,  Clearing},	/* BGP_Start                    */
    {bgp_stop,			Clearing},	/* BGP_Stop                     */
    {bgp_stop,			Clearing},	/* TCP_connection_open          */
    {bgp_stop,			Clearing},	/* TCP_connection_closed        */
    {bgp_stop,			Clearing},	/* TCP_connection_open_failed   */
    {bgp_stop,			Clearing},	/* TCP_fatal_error              */
    {bgp_stop,			Clearing},	/* ConnectRetry_timer_expired   */
    {bgp_stop,			Clearing},	/* Hold_Timer_expired           */
    {bgp_stop,			Clearing},	/* KeepAlive_timer_expired      */
    {bgp_stop,			Clearing},	/* Receive_OPEN_message         */
    {bgp_stop,			Clearing},	/* Receive_KEEPALIVE_message    */
    {bgp_stop,			Clearing},	/* Receive_UPDATE_message       */
    {bgp_stop,			Clearing},	/* Receive_NOTIFICATION_message */
    {bgp_clearing_completed,    Idle},		/* Clearing_Completed           */
  },
  {
    /* Deleted, */
    {bgp_ignore,  Deleted},	/* BGP_Start                    */
    {bgp_ignore,  Deleted},	/* BGP_Stop                     */
    {bgp_ignore,  Deleted},	/* TCP_connection_open          */
    {bgp_ignore,  Deleted},	/* TCP_connection_closed        */
    {bgp_ignore,  Deleted},	/* TCP_connection_open_failed   */
    {bgp_ignore,  Deleted},	/* TCP_fatal_error              */
    {bgp_ignore,  Deleted},	/* ConnectRetry_timer_expired   */
    {bgp_ignore,  Deleted},	/* Hold_Timer_expired           */
    {bgp_ignore,  Deleted},	/* KeepAlive_timer_expired      */
    {bgp_ignore,  Deleted},	/* Receive_OPEN_message         */
    {bgp_ignore,  Deleted},	/* Receive_KEEPALIVE_message    */
    {bgp_ignore,  Deleted},	/* Receive_UPDATE_message       */
    {bgp_ignore,  Deleted},	/* Receive_NOTIFICATION_message */
    {bgp_ignore,  Deleted},	/* Clearing_Completed           */
  },
};

static const char *bgp_event_str[] =
{
  NULL,
  "BGP_Start",
  "BGP_Stop",
  "TCP_connection_open",
  "TCP_connection_closed",
  "TCP_connection_open_failed",
  "TCP_fatal_error",
  "ConnectRetry_timer_expired",
  "Hold_Timer_expired",
  "KeepAlive_timer_expired",
  "Receive_OPEN_message",
  "Receive_KEEPALIVE_message",
  "Receive_UPDATE_message",
  "Receive_NOTIFICATION_message",
  "Clearing_Completed",
};

/* Execute event process. */
int
bgp_event (struct thread *thread)
{
  int event;
  struct peer *peer;
  int ret;

  peer = THREAD_ARG (thread);
  event = THREAD_VAL (thread);

  ret = bgp_event_update(peer, event);

  return (ret);
}

int
bgp_event_update (struct peer *peer, int event)
{
  int next;
  int ret = 0;
  struct peer *other;
  int passive_conn = 0;

  other = peer->doppelganger;
  passive_conn = (CHECK_FLAG(peer->sflags, PEER_STATUS_ACCEPT_PEER)) ? 1 : 0;

  /* Logging this event. */
  next = FSM [peer->status -1][event - 1].next_state;

  if (BGP_DEBUG (fsm, FSM) && peer->status != next)
    plog_debug (peer->log, "%s [FSM] %s (%s->%s)", peer->host,
	       bgp_event_str[event],
	       LOOKUP (bgp_status_msg, peer->status),
	       LOOKUP (bgp_status_msg, next));

  /* Call function. */
  if (FSM [peer->status -1][event - 1].func)
    ret = (*(FSM [peer->status - 1][event - 1].func))(peer);

  /* When function do not want proceed next job return -1. */
  if (ret >= 0)
    {
      if (ret == 1 && next == Established)
        {
          /* The case when doppelganger swap accurred in bgp_establish.
             Update the peer pointer accordingly */
          peer = other;
        }

      /* If status is changed. */
      if (next != peer->status)
        bgp_fsm_change_status (peer, next);
      
      /* Make sure timer is set. */
      bgp_timer_set (peer);

    }
  else if (!passive_conn && peer->bgp)
    {
      /* If we got a return value of -1, that means there was an error, restart
       * the FSM. If the peer structure was deleted
       */
      bgp_fsm_change_status(peer, Idle);
      bgp_timer_set(peer);
    }
  return ret;
}
