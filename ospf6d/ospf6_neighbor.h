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

#ifndef OSPF6_NEIGHBOR_H
#define OSPF6_NEIGHBOR_H

/* Neighbor structure */
struct ospf6_neighbor
{
  /* Neighbor Router ID String */
  char str[32];

  /* OSPFv3 Interface this neighbor belongs to */
  struct ospf6_interface *ospf6_interface;

  /* Neighbor state */
  u_char state;
  struct timeval last_changed;

  /* Neighbor Router ID */
  u_int32_t router_id;

  /* Router Priority of this neighbor */
  u_char priority;

  u_int32_t ifid;
  u_int32_t dr;
  u_int32_t bdr;
  u_int32_t prevdr;
  u_int32_t prevbdr;

  /* Link-LSA's options field */
  char options[3];

  /* IPaddr of I/F on our side link */
  struct in6_addr hisaddr;

  /* new */
  struct ospf6_lsdb *summary_list;
  struct ospf6_lsdb *request_list;
  struct ospf6_lsdb *retrans_list;

  /* For Database Exchange */
  u_char               dbdesc_bits;
  u_int32_t            dbdesc_seqnum;
  struct ospf6_dbdesc *dbdesc_previous;

  /* last received DD , including OSPF capability of this neighbor */
  struct ospf6_dbdesc last_dd;

  /* LSAs to retransmit to this neighbor */
  list dbdesc_lsa;

  /* placeholder for DbDesc */
  struct iovec dbdesc_last_send[1024];

  struct thread *inactivity_timer;

  /* DbDesc */
  struct thread *thread_send_dbdesc;
  struct thread *thread_rxmt_dbdesc;
  list dbdesclist;
  struct ospf6_lsdb *dbdesc_list;

  /* LSReq */
  struct thread *thread_send_lsreq;
  struct thread *thread_rxmt_lsreq;

  /* LSUpdate */
  struct thread *send_update;
  struct thread *thread_send_update;
  struct thread *thread_rxmt_update;

  /* statistics */
  u_int message_send[OSPF6_MESSAGE_TYPE_MAX];
  u_int message_receive[OSPF6_MESSAGE_TYPE_MAX];
  u_int lsa_send[OSPF6_MESSAGE_TYPE_MAX];
  u_int lsa_receive[OSPF6_MESSAGE_TYPE_MAX];

  u_int ospf6_stat_state_changed;
  u_int ospf6_stat_seqnum_mismatch;
  u_int ospf6_stat_bad_lsreq;
  u_int ospf6_stat_oneway_received;
  u_int ospf6_stat_inactivity_timer;
  u_int ospf6_stat_dr_election;
  u_int ospf6_stat_retrans_dbdesc;
  u_int ospf6_stat_retrans_lsreq;
  u_int ospf6_stat_retrans_lsupdate;
  u_int ospf6_stat_received_lsa;
  u_int ospf6_stat_received_lsupdate;

  struct timeval tv_last_hello_received;
};

extern char *ospf6_neighbor_state_string[];


/* Function Prototypes */
int
ospf6_neighbor_last_dbdesc_release (struct thread *);

void
ospf6_neighbor_lslist_clear (struct ospf6_neighbor *);

void
ospf6_neighbor_summary_add (struct ospf6_lsa *, struct ospf6_neighbor *);
void
ospf6_neighbor_summary_remove (struct ospf6_lsa *, struct ospf6_neighbor *);

void
ospf6_neighbor_request_add (struct ospf6_lsa *, struct ospf6_neighbor *);
void
ospf6_neighbor_request_remove (struct ospf6_lsa *, struct ospf6_neighbor *);

void
ospf6_neighbor_retrans_add (struct ospf6_lsa *, struct ospf6_neighbor *);
void
ospf6_neighbor_retrans_remove (struct ospf6_lsa *, struct ospf6_neighbor *);

void
ospf6_neighbor_dbdesc_add (struct ospf6_lsa *lsa,
                           struct ospf6_neighbor *nei);
void
ospf6_neighbor_dbdesc_remove (struct ospf6_lsa *lsa,
                              struct ospf6_neighbor *nei);

void
ospf6_neighbor_dbex_init (struct ospf6_neighbor *nei);

void
ospf6_neighbor_thread_cancel_all (struct ospf6_neighbor *);

struct ospf6_neighbor *
ospf6_neighbor_create (u_int32_t, struct ospf6_interface *);
void
ospf6_neighbor_delete (struct ospf6_neighbor *);
struct ospf6_neighbor *
ospf6_neighbor_lookup (u_int32_t, struct ospf6_interface *);

void ospf6_neighbor_init ();

#endif /* OSPF6_NEIGHBOR_H */

