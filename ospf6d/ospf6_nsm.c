/*
 * Copyright (C) 1999 Yasuhiro Ohara
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the 
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330, 
 * Boston, MA 02111-1307, USA.  
 */

#include "ospf6d.h"

static int
nbs_full_change (struct ospf6_interface *ospf6_interface)
{
  CALL_FOREACH_LSA_HOOK (hook_interface, hook_change, ospf6_interface);
  return 0;
}

static int
nbs_change (state_t nbs_next, char *reason, struct ospf6_neighbor *o6n)
{
  state_t nbs_previous;

  nbs_previous = o6n->state;
  o6n->state = nbs_next;

  if (nbs_previous == nbs_next)
    return 0;

  /* statistics */
  o6n->ospf6_stat_state_changed++;
  gettimeofday (&o6n->last_changed, NULL);

  /* log */
  if (IS_OSPF6_DUMP_NEIGHBOR)
    {
      if (reason)
        zlog_info ("Neighbor status change %s: [%s]->[%s](%s)",
                   o6n->str,
                   ospf6_neighbor_state_string[nbs_previous],
                   ospf6_neighbor_state_string[nbs_next],
                   reason);
      else
        zlog_info ("Neighbor status change %s: [%s]->[%s]",
                   o6n->str,
                   ospf6_neighbor_state_string[nbs_previous],
                   ospf6_neighbor_state_string[nbs_next]);
    }

  if (nbs_previous == NBS_FULL || nbs_next == NBS_FULL)
    nbs_full_change (o6n->ospf6_interface);

  /* check for LSAs that already reached MaxAge */
  if ((nbs_previous == NBS_EXCHANGE || nbs_previous == NBS_LOADING) &&
      (nbs_next != NBS_EXCHANGE && nbs_next != NBS_LOADING))
    {
      ospf6_maxage_remover ();
    }

  CALL_CHANGE_HOOK (&neighbor_hook, o6n);

  return 0;
}

/* RFC2328 section 10.4 */
int
need_adjacency (struct ospf6_neighbor *o6n)
{

  if (o6n->ospf6_interface->state == IFS_PTOP)
    return 1;
  if (o6n->ospf6_interface->state == IFS_DR)
    return 1;
  if (o6n->ospf6_interface->state == IFS_BDR)
    return 1;
  if (o6n->router_id == o6n->ospf6_interface->dr)
    return 1;
  if (o6n->router_id == o6n->ospf6_interface->bdr)
    return 1;

  return 0;
}

int
hello_received (struct thread *thread)
{
  struct ospf6_neighbor *o6n;

  o6n = (struct ospf6_neighbor *) THREAD_ARG (thread);
  assert (o6n);

  if (IS_OSPF6_DUMP_NEIGHBOR)
    zlog_info ("Neighbor Event %s: *HelloReceived*", o6n->str);

  if (o6n->inactivity_timer)
    thread_cancel (o6n->inactivity_timer);

  o6n->inactivity_timer = thread_add_timer (master, inactivity_timer, o6n,
                                            o6n->ospf6_interface->dead_interval);
  if (o6n->state <= NBS_DOWN)
    nbs_change (NBS_INIT, "HelloReceived", o6n);
  return 0;
}

int
twoway_received (struct thread *thread)
{
  struct ospf6_neighbor *o6n;

  o6n = (struct ospf6_neighbor *) THREAD_ARG (thread);
  assert (o6n);

  if (o6n->state > NBS_INIT)
    return 0;

  if (IS_OSPF6_DUMP_NEIGHBOR)
    zlog_info ("Neighbor Event %s: *2Way-Received*", o6n->str);

  thread_add_event (master, neighbor_change, o6n->ospf6_interface, 0);

  if (!need_adjacency (o6n))
    {
      nbs_change (NBS_TWOWAY, "No Need Adjacency", o6n);
      return 0;
    }
  else
    nbs_change (NBS_EXSTART, "Need Adjacency", o6n);

  DD_MSBIT_SET (o6n->dbdesc_bits);
  DD_MBIT_SET (o6n->dbdesc_bits);
  DD_IBIT_SET (o6n->dbdesc_bits);

  if (o6n->thread_send_dbdesc)
    thread_cancel (o6n->thread_send_dbdesc);
  o6n->thread_send_dbdesc =
    thread_add_event (master, ospf6_send_dbdesc, o6n, 0);
  if (o6n->thread_rxmt_dbdesc)
    thread_cancel (o6n->thread_rxmt_dbdesc);
  o6n->thread_rxmt_dbdesc = (struct thread *) NULL;

  return 0;
}

int
negotiation_done (struct thread *thread)
{
  struct ospf6_neighbor *o6n;

  o6n = (struct ospf6_neighbor *) THREAD_ARG (thread);
  assert (o6n);

  if (o6n->state != NBS_EXSTART)
    return 0;

  if (IS_OSPF6_DUMP_NEIGHBOR)
    zlog_info ("Neighbor Event %s: *NegotiationDone*", o6n->str);

  nbs_change (NBS_EXCHANGE, "NegotiationDone", o6n);
  DD_IBIT_CLEAR (o6n->dbdesc_bits);

  return 0;
}

int
exchange_done (struct thread *thread)
{
  struct ospf6_neighbor *o6n;

  o6n = (struct ospf6_neighbor *) THREAD_ARG (thread);
  assert (o6n);

  if (o6n->state != NBS_EXCHANGE)
    return 0;

  if (o6n->thread_rxmt_dbdesc)
    thread_cancel (o6n->thread_rxmt_dbdesc);
  o6n->thread_rxmt_dbdesc = (struct thread *) NULL;

  if (IS_OSPF6_DUMP_NEIGHBOR)
    zlog_info ("Neighbor Event %s: *ExchangeDone*", o6n->str);

  ospf6_lsdb_remove_all (o6n->dbdesc_list);

  thread_add_timer (master, ospf6_neighbor_last_dbdesc_release, o6n,
                    o6n->ospf6_interface->dead_interval);

  if (o6n->request_list->count == 0)
    nbs_change (NBS_FULL, "Requestlist Empty", o6n);
  else
    {
      thread_add_event (master, ospf6_send_lsreq, o6n, 0);
      nbs_change (NBS_LOADING, "Requestlist Not Empty", o6n);
    }
  return 0;
}

int
loading_done (struct thread *thread)
{
  struct ospf6_neighbor *o6n;

  o6n = (struct ospf6_neighbor *) THREAD_ARG (thread);
  assert (o6n);

  if (o6n->state != NBS_LOADING)
    return 0;

  if (IS_OSPF6_DUMP_NEIGHBOR)
    zlog_info ("Neighbor Event %s: *LoadingDone*", o6n->str);

  assert (o6n->request_list->count == 0);

  nbs_change (NBS_FULL, "LoadingDone", o6n);

  return 0;
}

int
adj_ok (struct thread *thread)
{
  struct ospf6_neighbor *o6n;

  o6n = (struct ospf6_neighbor *) THREAD_ARG (thread);
  assert (o6n);

  if (IS_OSPF6_DUMP_NEIGHBOR)
    zlog_info ("Neighbor Event %s: *AdjOK?*", o6n->str);

  if (o6n->state == NBS_TWOWAY)
    {
      if (!need_adjacency (o6n))
        {
          nbs_change (NBS_TWOWAY, "No Need Adjacency", o6n);
          return 0;
        }
      else
        nbs_change (NBS_EXSTART, "Need Adjacency", o6n);

      DD_MSBIT_SET (o6n->dbdesc_bits);
      DD_MBIT_SET (o6n->dbdesc_bits);
      DD_IBIT_SET (o6n->dbdesc_bits);

      if (o6n->thread_send_dbdesc)
        thread_cancel (o6n->thread_send_dbdesc);
      o6n->thread_send_dbdesc =
        thread_add_event (master, ospf6_send_dbdesc, o6n, 0);

      return 0;
    }

  if (o6n->state >= NBS_EXSTART)
    {
      if (need_adjacency (o6n))
        return 0;
      else
        {
          nbs_change (NBS_TWOWAY, "No Need Adjacency", o6n);
          ospf6_neighbor_lslist_clear (o6n);
        }
    }
  return 0;
}

int
seqnumber_mismatch (struct thread *thread)
{
  struct ospf6_neighbor *o6n;

  o6n = (struct ospf6_neighbor *) THREAD_ARG (thread);
  assert (o6n);

  if (o6n->state < NBS_EXCHANGE)
    return 0;

  /* statistics */
  o6n->ospf6_stat_seqnum_mismatch++;

  if (IS_OSPF6_DUMP_NEIGHBOR)
    zlog_info ("Neighbor Event %s: *SeqNumberMismatch*", o6n->str);

  nbs_change (NBS_EXSTART, "SeqNumberMismatch", o6n);

  DD_MSBIT_SET (o6n->dbdesc_bits);
  DD_MBIT_SET (o6n->dbdesc_bits);
  DD_IBIT_SET (o6n->dbdesc_bits);
  ospf6_neighbor_lslist_clear (o6n);

  if (o6n->thread_send_dbdesc)
    thread_cancel (o6n->thread_send_dbdesc);
  o6n->thread_send_dbdesc =
    thread_add_event (master, ospf6_send_dbdesc, o6n, 0);

  return 0;
}

int
bad_lsreq (struct thread *thread)
{
  struct ospf6_neighbor *o6n;

  o6n = (struct ospf6_neighbor *) THREAD_ARG (thread);
  assert (o6n);

  if (o6n->state < NBS_EXCHANGE)
    return 0;

  /* statistics */
  o6n->ospf6_stat_bad_lsreq++;

  if (IS_OSPF6_DUMP_NEIGHBOR)
    zlog_info ("Neighbor Event %s: *BadLSReq*", o6n->str);

  nbs_change (NBS_EXSTART, "BadLSReq", o6n);

  DD_MSBIT_SET (o6n->dbdesc_bits);
  DD_MBIT_SET (o6n->dbdesc_bits);
  DD_IBIT_SET (o6n->dbdesc_bits);
  ospf6_neighbor_lslist_clear (o6n);

  if (o6n->thread_send_dbdesc)
    thread_cancel (o6n->thread_send_dbdesc);
  o6n->thread_send_dbdesc =
    thread_add_event (master, ospf6_send_dbdesc, o6n, 0);

  return 0;
}

int
oneway_received (struct thread *thread)
{
  struct ospf6_neighbor *o6n;

  o6n = (struct ospf6_neighbor *) THREAD_ARG (thread);
  assert (o6n);

  if (o6n->state < NBS_TWOWAY)
    return 0;

  /* statistics */
  o6n->ospf6_stat_oneway_received++;

  if (IS_OSPF6_DUMP_NEIGHBOR)
    zlog_info ("Neighbor Event %s: *1Way-Received*", o6n->str);

  nbs_change (NBS_INIT, "1Way-Received", o6n);

  thread_add_event (master, neighbor_change, o6n->ospf6_interface, 0);

  ospf6_neighbor_thread_cancel_all (o6n);
  ospf6_neighbor_lslist_clear (o6n);
  return 0;
}

int
inactivity_timer (struct thread *thread)
{
  struct ospf6_neighbor *o6n;

  o6n = (struct ospf6_neighbor *) THREAD_ARG (thread);
  assert (o6n);

  /* statistics */
  o6n->ospf6_stat_inactivity_timer++;

  if (IS_OSPF6_DUMP_NEIGHBOR)
    zlog_info ("Neighbor Event %s: *InactivityTimer*", o6n->str);

  o6n->inactivity_timer = NULL;
  o6n->dr = o6n->bdr = o6n->prevdr = o6n->prevbdr = 0;
  nbs_change (NBS_DOWN, "InactivityTimer", o6n);

  thread_add_event (master, neighbor_change, o6n->ospf6_interface, 0);

  listnode_delete (o6n->ospf6_interface->neighbor_list, o6n);
  ospf6_neighbor_delete (o6n);

  return 0;
}

