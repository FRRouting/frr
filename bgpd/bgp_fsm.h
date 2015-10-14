/* BGP-4 Finite State Machine   
   From RFC1771 [A Border Gateway Protocol 4 (BGP-4)]
   Copyright (C) 1998 Kunihiro Ishiguro

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

#ifndef _QUAGGA_BGP_FSM_H
#define _QUAGGA_BGP_FSM_H

/* Macro for BGP read, write and timer thread.  */
#define BGP_READ_ON(T,F,V)			\
  do {						\
    if (!(T) && (peer->status != Deleted))	\
      THREAD_READ_ON(bm->master,T,F,peer,V);	\
  } while (0)

#define BGP_READ_OFF(T)				\
  do {						\
    if (T)					\
      THREAD_READ_OFF(T);			\
  } while (0)

#define BGP_WRITE_ON(T,F,V)			\
  do {						\
    if (!(T) && (peer->status != Deleted))	\
      THREAD_WRITE_ON(bm->master,(T),(F),peer,(V)); \
  } while (0)

#define BGP_PEER_WRITE_ON(T,F,V, peer)			\
  do {							\
    if (!(T) && ((peer)->status != Deleted))		\
      THREAD_WRITE_ON(bm->master,(T),(F),(peer),(V));	\
  } while (0)

#define BGP_WRITE_OFF(T)			\
  do {						\
    if (T)					\
      THREAD_WRITE_OFF(T);			\
  } while (0)

#define BGP_TIMER_ON(T,F,V)			\
  do {						\
    if (!(T) && (peer->status != Deleted))	\
      THREAD_TIMER_ON(bm->master,(T),(F),peer,(V)); \
  } while (0)

#define BGP_TIMER_OFF(T)			\
  do {						\
    if (T)					\
      THREAD_TIMER_OFF(T);			\
  } while (0)

#define BGP_EVENT_ADD(P,E)			\
  do {						\
    if ((P)->status != Deleted)			\
      thread_add_event (bm->master, bgp_event, (P), (E)); \
  } while (0)

#define BGP_EVENT_FLUSH(P)			\
  do { 						\
    assert (peer); 				\
    thread_cancel_event (bm->master, (P)); 		\
  } while (0)

#define BGP_MSEC_JITTER 10

/* Prototypes. */
extern void bgp_fsm_nht_update(struct peer *, int valid);
extern int bgp_event (struct thread *);
extern int bgp_event_update (struct peer *, int event);
extern int bgp_stop (struct peer *peer);
extern void bgp_timer_set (struct peer *);
extern int bgp_routeadv_timer (struct thread *);
extern void bgp_fsm_change_status (struct peer *peer, int status);
extern const char *peer_down_str[];
extern void bgp_update_delay_end (struct bgp *);
extern void bgp_maxmed_update (struct bgp *);
extern int bgp_maxmed_onstartup_configured (struct bgp *);
extern int bgp_maxmed_onstartup_active (struct bgp *);

/**
 * Start the route advertisement timer (that honors MRAI) for all the
 * peers. Typically called at the end of initial convergence, coming
 * out of read-only mode.
 */
extern void bgp_start_routeadv (struct bgp *);

/**
 * See if the route advertisement timer needs to be adjusted for a
 * peer. For example, if the last update was written to the peer a
 * long while back, we don't need to wait for the periodic advertisement
 * timer to expire to send the new set of prefixes. It should fire
 * instantly and updates should go out sooner.
 */
extern void bgp_adjust_routeadv (struct peer *);

#endif /* _QUAGGA_BGP_FSM_H */
