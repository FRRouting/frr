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

#ifndef OSPF6_INTERFACE_H
#define OSPF6_INTERFACE_H

#include "ospf6_message.h"

/* This file defines interface data structure. */

struct ospf6_interface
{
  /* IF info from zebra */
  struct interface *interface;

  /* back pointer */
  struct ospf6_area *area;

  /* list of ospf6 neighbor */
  list neighbor_list;

  /* linklocal address of this I/F */
  struct in6_addr *lladdr;

  /* Interface ID; same as ifindex */
  u_int32_t if_id;

  /* ospf6 instance id */
  u_char instance_id;

  /* I/F transmission delay */
  u_int32_t transdelay;

  /* Router Priority */
  u_char priority;

  /* Timers */
  u_int16_t hello_interval;
  u_int16_t dead_interval;
  u_int32_t rxmt_interval;

  /* Cost */
  u_int32_t cost;

  /* I/F MTU */
  u_int32_t ifmtu;

  /* Interface State */
  u_char state;

  /* OSPF6 Interface flag */
  char flag;

  /* Decision of DR Election */
  u_int32_t dr;
  u_int32_t bdr;
  u_int32_t prevdr;
  u_int32_t prevbdr;

  /* Ongoing Tasks */
  struct thread *thread_send_hello;
  struct thread *thread_send_lsack_delayed;

  /* LSAs to Delayed Acknowledge */
  struct ospf6_lsdb *ack_list;

  /* Linklocal LSA Database: includes Link-LSA */
  struct ospf6_lsdb *lsdb;

  /* statistics */
  u_int ospf6_stat_dr_election;
  u_int ospf6_stat_delayed_lsack;

  struct ospf6_message_stat message_stat[OSPF6_MESSAGE_TYPE_MAX];

  void (*foreach_nei) (struct ospf6_interface *, void *, int,
                       void (*func) (void *, int, void *));

  struct thread *maxage_remover;

  /* route-map to filter connected prefix */
  char *plist_name;
};

extern char *ospf6_interface_state_string[];

#define OSPF6_INTERFACE_FLAG_PASSIVE      0x01
#define OSPF6_INTERFACE_FLAG_FORCE_PREFIX 0x02


/* Function Prototypes */

void
ospf6_interface_schedule_maxage_remover (void *arg, int val, void *obj);

struct ospf6_interface *
ospf6_interface_create (struct interface *);
void
ospf6_interface_delete (struct ospf6_interface *);

struct ospf6_interface *
ospf6_interface_lookup_by_index (int);
struct ospf6_interface *
ospf6_interface_lookup_by_name (char *);

void ospf6_interface_if_add (struct interface *);
void ospf6_interface_if_del (struct interface *);
void ospf6_interface_state_update (struct interface *);
void ospf6_interface_address_update (struct interface *);

void ospf6_interface_init ();

#if 0
int
ospf6_interface_count_neighbor_in_state (u_char state,
                                         struct ospf6_interface *o6i);
int
ospf6_interface_count_full_neighbor (struct ospf6_interface *);
#endif

int ospf6_interface_is_enabled (u_int32_t ifindex);

void
ospf6_interface_delayed_ack_add (struct ospf6_lsa *lsa,
                                 struct ospf6_interface *o6i);
void
ospf6_interface_delayed_ack_remove (struct ospf6_lsa *lsa,
                                    struct ospf6_interface *o6i);

void
ospf6_interface_statistics_show (struct vty *vty,
                                 struct ospf6_interface *o6i);

#endif /* OSPF6_INTERFACE_H */

